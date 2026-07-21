use super::manifest::validate_repo_path;
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

pub(super) fn git_object(
    root: &Path,
    revision: &str,
    relative: &str,
    limit: u64,
) -> Result<Option<Vec<u8>>> {
    validate_repo_path(relative)?;
    if revision.is_empty() || revision.starts_with('-') || revision.chars().any(char::is_control) {
        bail!("invalid compatibility base revision");
    }
    let revision = format!("{revision}^{{commit}}");
    let resolved = Command::new("git")
        .args(["rev-parse", "--verify", "--end-of-options", &revision])
        .current_dir(root)
        .output()
        .context("cannot resolve compatibility base revision")?;
    if !resolved.status.success() {
        bail!("cannot resolve compatibility base revision");
    }
    let resolved = std::str::from_utf8(&resolved.stdout)
        .context("compatibility base object ID is not UTF-8")?
        .trim();
    if !matches!(resolved.len(), 40 | 64) || !resolved.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("git returned an invalid compatibility base object ID");
    }

    let listing = Command::new("git")
        .args([
            "ls-tree",
            "-z",
            "--full-name",
            "--name-only",
            resolved,
            "--",
            relative,
        ])
        .current_dir(root)
        .output()
        .with_context(|| format!("cannot inspect base path `{relative}`"))?;
    if !listing.status.success() {
        bail!("git could not inspect base compatibility path `{relative}`");
    }
    if listing.stdout.is_empty() {
        return Ok(None);
    }
    let mut expected_listing = relative.as_bytes().to_vec();
    expected_listing.push(0);
    if listing.stdout != expected_listing {
        bail!("git returned an ambiguous base compatibility path `{relative}`");
    }

    let object = format!("{resolved}:{relative}");
    let size = Command::new("git")
        .args(["cat-file", "-s", &object])
        .current_dir(root)
        .output()
        .with_context(|| format!("cannot inspect base object `{relative}`"))?;
    if !size.status.success() {
        bail!("git could not size base compatibility file `{relative}`");
    }
    let size = std::str::from_utf8(&size.stdout)
        .context("git object size is not UTF-8")?
        .trim()
        .parse::<u64>()
        .context("git object size is not a u64")?;
    if size > limit {
        bail!("base compatibility file `{relative}` exceeds its byte limit");
    }
    let output = Command::new("git")
        .args(["show", "--no-textconv", &object])
        .current_dir(root)
        .output()
        .with_context(|| format!("cannot read base object `{relative}`"))?;
    if !output.status.success() {
        bail!("git could not read base compatibility file `{relative}`");
    }
    Ok(Some(output.stdout))
}
