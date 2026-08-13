//! Bounded Git status observations for change-set and rewind previews.
//!
//! This is deliberately separate from the model-facing `git_diff` tool. A porcelain status is a
//! byte protocol: filenames may contain newlines and must therefore remain NUL-delimited until the
//! typed `iteron-changeset` parser sees them. The command uses the same absolute executable,
//! contained git-dir, configuration neutralisation, deadline, process-group teardown, and output
//! ceilings as every other production Git observation in this crate.

use crate::git_filters::discover_filter_drivers;
use crate::git_harness::{
    GIT_TIMEOUT, STDERR_LIMIT, hardened_args, hardened_git_command, resolve_git_executable,
    resolve_repository_layout, run_command_bounded,
};
use std::ffi::OsString;
use std::path::Path;

/// Enough for the maximum 1,000-entry change-set with long paths, while still refusing a status
/// stream large enough to monopolise the frontend.
const STATUS_OUTPUT_LIMIT: usize = 2 * 1024 * 1024;

pub(crate) async fn run_git_status_porcelain(root: &Path) -> Result<Vec<u8>, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("workspace root: {error}"))?;
    let repository = resolve_repository_layout(&root)?;
    let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &root)
        .map_err(|error| format!("could not resolve trusted Git: {error}"))?;
    let filter_drivers = discover_filter_drivers(&git, &repository).await?;
    let operation = [
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=dirty",
    ]
    .into_iter()
    .map(OsString::from);
    let args = hardened_args(&filter_drivers, operation);
    let mut command = hardened_git_command(&git, &repository, &args);
    let status_output_limit =
        iteron_tunables::param_usize("tools.git_changes.status_output_limit", STATUS_OUTPUT_LIMIT);
    let captured = run_command_bounded(
        &mut command,
        iteron_tunables::param_duration("tools.git_harness.git_timeout", GIT_TIMEOUT),
        status_output_limit,
        iteron_tunables::param_integer("tools.git_harness.stderr_limit", STDERR_LIMIT),
    )
    .await
    .map_err(|error| format!("could not run bounded Git status: {error}"))?;
    if !captured.status.success() {
        return Err(format!(
            "Git status failed (exit {}): {}",
            captured.status.code().unwrap_or(-1),
            captured.stderr.render("Git stderr").trim()
        ));
    }
    if captured.stdout.truncated() {
        return Err(format!(
            "Git status exceeded the {status_output_limit}-byte observation ceiling"
        ));
    }
    Ok(captured.stdout.retained_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn status_preserves_the_nul_protocol_and_untracked_population() {
        let root = std::env::temp_dir().join(format!(
            "core-git-status-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let init = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(init.success());
        std::fs::write(root.join("new file.txt"), "new").unwrap();

        let raw = run_git_status_porcelain(&root).await.unwrap();
        assert!(raw.ends_with(&[0]));
        assert!(raw.windows(15).any(|bytes| bytes == b"?? new file.txt"));
        std::fs::remove_dir_all(root).ok();
    }
}
