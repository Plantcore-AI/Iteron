//! Bounded discovery and command-scope neutralization inputs for Git content filters.

use crate::git_harness::{
    GIT_TIMEOUT, RepositoryLayout, ResolvedGit, STDERR_LIMIT, hardened_args, hardened_git_command,
    run_command_bounded,
};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const FILTER_CONFIG_LIMIT: usize = 64 * 1024;
pub(crate) const MAX_FILTER_DRIVERS: usize = 128;
const MAX_FILTER_DRIVER_BYTES: usize = 4 * 1024;
const FILTER_CONFIG_PATTERN: &str = r"^filter\..*\.(clean|smudge|process|required)$";

#[derive(Clone, Debug, PartialEq, Eq)]
struct FilterCacheKey {
    git_dir: PathBuf,
    config_sha256: String,
    pattern: String,
    source_limit: usize,
}

type FilterCacheEntry = Option<(FilterCacheKey, Vec<String>)>;

static FILTER_CACHE: OnceLock<Mutex<FilterCacheEntry>> = OnceLock::new();

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
            if drivers.len()
                > iteron_tunables::param_integer(
                    "tools.git_filters.max_filter_drivers",
                    MAX_FILTER_DRIVERS,
                )
                || driver_bytes
                    > iteron_tunables::param_integer(
                        "tools.git_filters.max_filter_driver_bytes",
                        MAX_FILTER_DRIVER_BYTES,
                    )
            {
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
    discover_filter_drivers_bounded(
        git,
        repository,
        iteron_tunables::param_duration("tools.git_harness.git_timeout", GIT_TIMEOUT),
        iteron_tunables::param_integer(
            "tools.git_filters.filter_config_limit",
            FILTER_CONFIG_LIMIT,
        ),
    )
    .await
}

pub(crate) async fn discover_filter_drivers_bounded(
    git: &ResolvedGit,
    repository: &RepositoryLayout,
    timeout: Duration,
    output_max_bytes: usize,
) -> Result<Vec<String>, String> {
    let pattern = iteron_tunables::param_str(
        "tools.git_filters.filter_config_pattern",
        FILTER_CONFIG_PATTERN,
    );
    let source_limit = output_max_bytes.min(iteron_tunables::param_integer(
        "tools.git_filters.filter_config_limit",
        FILTER_CONFIG_LIMIT,
    ));
    let before = filter_cache_key(repository, pattern, source_limit);
    if let Some(key) = before.as_ref()
        && let Some((cached_key, drivers)) = FILTER_CACHE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        && cached_key == key
    {
        return Ok(drivers.clone());
    }
    let operation = [
        "config",
        "--null",
        "--name-only",
        "--includes",
        "--get-regexp",
        pattern,
    ]
    .into_iter()
    .map(OsString::from);
    let args = hardened_args(&[], operation);
    let mut command = hardened_git_command(git, repository, &args);
    let captured = run_command_bounded(
        &mut command,
        timeout,
        source_limit,
        iteron_tunables::param_integer("tools.git_harness.stderr_limit", STDERR_LIMIT),
    )
    .await
    .map_err(|error| format!("could not inspect Git filter config: {error}"))?;

    let no_matches = captured.status.code() == Some(1) && captured.stdout.total == 0;
    if !no_matches && !captured.status.success() {
        return Err(format!(
            "could not inspect Git filter config (exit {}): {}",
            captured.status.code().unwrap_or(-1),
            captured.stderr.render("Git config stderr").trim()
        ));
    }
    if captured.stdout.truncated() {
        return Err(format!(
            "Git filter config exceeded the {source_limit}-byte inspection limit"
        ));
    }
    let drivers = if no_matches {
        Vec::new()
    } else {
        parse_filter_drivers(&captured.stdout.retained_bytes())?
    };
    if let Some(before) = before
        && filter_cache_key(repository, pattern, source_limit).as_ref() == Some(&before)
    {
        *FILTER_CACHE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((before, drivers.clone()));
    }
    Ok(drivers)
}

/// Fingerprint only the local configuration Git is allowed to read. Includes deliberately bypass
/// the memo because their transitive origins may live outside the repository; executing the
/// bounded inspection again is cheaper and safer than guessing an incomplete invalidation set.
fn filter_cache_key(
    repository: &RepositoryLayout,
    pattern: &str,
    source_limit: usize,
) -> Option<FilterCacheKey> {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"iteron-git-filter-config-v1\0");
    for name in ["config", "config.worktree"] {
        let path = repository.git_dir.join(name);
        digest.update(name.as_bytes());
        match read_cacheable_config(&path, source_limit)? {
            Some(bytes) => {
                let lower = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
                if lower.contains("[include") {
                    return None;
                }
                digest.update((bytes.len() as u64).to_be_bytes());
                digest.update(bytes);
            }
            None => digest.update(0_u64.to_be_bytes()),
        }
    }
    Some(FilterCacheKey {
        git_dir: repository.git_dir.clone(),
        config_sha256: format!("{:x}", digest.finalize()),
        pattern: pattern.to_owned(),
        source_limit,
    })
}

fn read_cacheable_config(path: &Path, source_limit: usize) -> Option<Option<Vec<u8>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(None),
        Err(_) => return None,
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > source_limit as u64
    {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    (bytes.len() <= source_limit).then_some(Some(bytes))
}
