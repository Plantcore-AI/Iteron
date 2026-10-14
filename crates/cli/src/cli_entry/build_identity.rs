//! Build identity and local staleness presentation; no network authority.

pub(crate) const BUILD_COMMIT: &str = match option_env!("ITERON_BUILD_COMMIT") {
    Some(commit) => commit,
    None => "unknown",
};
pub(crate) const BUILD_DATE: &str = match option_env!("ITERON_BUILD_DATE") {
    Some(date) => date,
    None => "unknown",
};
/// Past this age the compiled-in provider catalog is old enough to have retired model ids, whose
/// 400 is then classified as permanent. Purely local arithmetic — no network, no update check.
pub(crate) const BUILD_STALE_AFTER_DAYS: i64 = 90;

/// `--version` text. `-V` keeps the bare `iteron <semver>` that release smoke tests match exactly.
pub(crate) fn long_version() -> &'static str {
    static LONG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    LONG.get_or_init(|| {
        format!(
            "{} ({} {})",
            env!("CARGO_PKG_VERSION"),
            iteron_tunables::param_str("cli.main.build_commit", BUILD_COMMIT),
            iteron_tunables::param_str("cli.main.build_date", BUILD_DATE)
        )
    })
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard Hinnant's `days_from_civil`).
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Parse a stamped `YYYY-MM-DD` build date into days since the epoch. An unstamped or malformed
/// value yields `None`, and an unknown age never produces a claim about it.
pub(crate) fn build_date_days(date: &str) -> Option<i64> {
    let mut fields = date.split('-');
    let year: i64 = fields.next()?.parse().ok()?;
    let month: i64 = fields.next()?.parse().ok()?;
    let day: i64 = fields.next()?.parse().ok()?;
    if fields.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

/// One line, on stderr, when this binary is old enough that its compiled-in facts have aged out.
pub(crate) fn staleness_note(date: &str, now_unix_secs: i64) -> Option<String> {
    let age = now_unix_secs.div_euclid(86_400) - build_date_days(date)?;
    (age > iteron_tunables::param_integer("cli.main.build_stale_after_days", BUILD_STALE_AFTER_DAYS)).then(|| {
        format!(
            "warning: this iteron build is {age} days old (built {date}, commit {BUILD_COMMIT}); its compiled-in provider catalog may name retired models — reinstall with the installer in the latest release"
        )
    })
}

pub(crate) fn warn_if_stale() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default();
    if let Some(note) = staleness_note(
        iteron_tunables::param_str("cli.main.build_date", BUILD_DATE),
        now,
    ) {
        eprintln!("{note}");
    }
}
