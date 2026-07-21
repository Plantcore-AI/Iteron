//! Bounded discovery and command-scope neutralization inputs for Git content filters.

use crate::git_harness::{
    GIT_TIMEOUT, RepositoryLayout, ResolvedGit, STDERR_LIMIT, hardened_args, hardened_git_command,
    run_command_bounded,
};
use std::collections::BTreeSet;
use std::ffi::OsString;

const FILTER_CONFIG_LIMIT: usize = 64 * 1024;
pub(crate) const MAX_FILTER_DRIVERS: usize = 128;
const MAX_FILTER_DRIVER_BYTES: usize = 4 * 1024;
const FILTER_CONFIG_PATTERN: &str = r"^filter\..*\.(clean|smudge|process|required)$";

/// Parse `git config --null --name-only` into `filter.<driver>` prefixes under count and byte
/// ceilings, preventing repository config from expanding the command line without bound.
pub(crate) fn parse_filter_drivers(bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut drivers = BTreeSet::new();
    let mut driver_bytes = 0_usize;

    for raw_key in bytes.split(|byte| *byte == 0).filter(|key| !key.is_empty()) {
        let key = std::str::from_utf8(raw_key)
            .map_err(|_| "Git filter config contained a non-UTF-8 key".to_owned())?;
        if key.chars().any(char::is_control) || key.contains('=') {
            return Err("Git filter config contained an unsafe key".to_owned());
        }
        let normalized = key.to_ascii_lowercase();
        let Some((normalized_driver, entry)) = normalized.rsplit_once('.') else {
            return Err(format!("unexpected Git filter config key: {key}"));
        };
        if !normalized_driver.starts_with("filter.")
            || normalized_driver == "filter."
            || !matches!(entry, "clean" | "smudge" | "process" | "required")
        {
            return Err(format!("unexpected Git filter config key: {key}"));
        }
        let driver = key[..key.len() - entry.len() - 1].to_owned();
        if drivers.insert(driver.clone()) {
            driver_bytes = driver_bytes.saturating_add(driver.len());
            if drivers.len() > MAX_FILTER_DRIVERS || driver_bytes > MAX_FILTER_DRIVER_BYTES {
                return Err(format!(
                    "Git filter config exceeds the defensive limit ({MAX_FILTER_DRIVERS} drivers, \
                     {MAX_FILTER_DRIVER_BYTES} key bytes)"
                ));
            }
        }
    }

    Ok(drivers.into_iter().collect())
}

/// Read effective local filter key names without evaluating worktree contents. Values never enter
/// Core; every discovered executable key is replaced by a command-scoped inert value.
pub(crate) async fn discover_filter_drivers(
    git: &ResolvedGit,
    repository: &RepositoryLayout,
) -> Result<Vec<String>, String> {
    let operation = [
        "config",
        "--null",
        "--name-only",
        "--includes",
        "--get-regexp",
        FILTER_CONFIG_PATTERN,
    ]
    .into_iter()
    .map(OsString::from);
    let args = hardened_args(&[], operation);
    let mut command = hardened_git_command(git, repository, &args);
    let captured =
        run_command_bounded(&mut command, GIT_TIMEOUT, FILTER_CONFIG_LIMIT, STDERR_LIMIT)
            .await
            .map_err(|error| format!("could not inspect Git filter config: {error}"))?;

    if captured.status.code() == Some(1) && captured.stdout.total == 0 {
        return Ok(Vec::new());
    }
    if !captured.status.success() {
        return Err(format!(
            "could not inspect Git filter config (exit {}): {}",
            captured.status.code().unwrap_or(-1),
            captured.stderr.render("Git config stderr").trim()
        ));
    }
    if captured.stdout.truncated() {
        return Err(format!(
            "Git filter config exceeded the {FILTER_CONFIG_LIMIT}-byte inspection limit"
        ));
    }
    parse_filter_drivers(&captured.stdout.retained_bytes())
}
