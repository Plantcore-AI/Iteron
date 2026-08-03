use super::{BuilderRef, Matrix, ReceiptRef, read_bounded_regular};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

mod git;

const RECEIPT_DIRECTORY: &str = "governance/client-conformance/runtime/";
const RECEIPT_PREFIX: &str = "governance/client-conformance/runtime/runtime-receipt-";
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_ATTESTATION_BYTES: u64 = 2 * 1024 * 1024;
const REPOSITORY: &str = "Plantcore-AI/core";
const BUILDER_WORKFLOW: &str = ".github/workflows/runtime-receipt.yml";
const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
const PLATFORM_ORDER: [&str; 5] = [
    "macos-arm64",
    "macos-x86_64",
    "linux-arm64",
    "linux-x86_64",
    "windows-x86_64",
];
const VERSION_ORDER: [&str; 2] = ["unix", "windows-msvc"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeReceipt {
    schema_version: u32,
    #[serde(rename = "type")]
    receipt_type: String,
    repository: Repository,
    tested_commit: String,
    tested_tree: String,
    builder_workflow: BuilderWorkflow,
    run: Run,
    platforms: Vec<Platform>,
    version_independence: Vec<VersionIndependence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Repository {
    name: String,
    id: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuilderWorkflow {
    path: String,
    commit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    id: u64,
    attempt: u64,
    event: String,
    head_branch: String,
    head_sha: String,
    workflow_path: String,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Platform {
    platform: String,
    target: String,
    runner: String,
    job: Job,
    steps: Steps,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: u64,
    runner_id: u64,
    runner_name: String,
    runner_group_id: u64,
    runner_group_name: String,
    labels: Vec<String>,
    conclusion: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Steps {
    target_tests: String,
    binary_build: String,
    binary_identity: String,
    native_client_smoke: String,
    version_independence: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionIndependence {
    operating_system: String,
    platform: String,
    job_id: u64,
    clients: Vec<String>,
    conclusion: String,
}

pub(super) fn validate(root: &Path, matrix: &Matrix) -> Result<()> {
    if let Some(builder) = &matrix.runtime_builder {
        validate_builder_reference(builder)?;
        git::validate_builder_configuration(root, builder)?;
    }
    let Some(reference) = &matrix.runtime_receipt else {
        return require_pending_state(matrix);
    };
    let builder = matrix
        .runtime_builder
        .as_ref()
        .context("a runtime_receipt requires a pinned runtime_builder")?;
    require_green_state(matrix)?;

    let (filename_run_id, filename_run_attempt) = validate_reference_shape(reference)?;
    let receipt_source = read_bounded_regular(root, &reference.path, MAX_RECEIPT_BYTES)?;
    validate_digest(&receipt_source, &reference.sha256, "runtime receipt")?;
    let receipt = parse_receipt(&receipt_source)?;
    if receipt.run.id != filename_run_id || receipt.run.attempt != filename_run_attempt {
        bail!("runtime receipt filename does not match its run id and attempt");
    }

    let attestation =
        read_bounded_regular(root, &reference.attestation_path, MAX_ATTESTATION_BYTES)?;
    validate_digest(
        &attestation,
        &reference.attestation_sha256,
        "runtime receipt attestation",
    )?;
    if !crate::schema_compat::parse_json_no_duplicates(&attestation, "runtime receipt attestation")?
        .is_object()
    {
        bail!("runtime receipt attestation must be a JSON object");
    }

    validate_receipt(&receipt, builder)?;
    git::validate_history(root, matrix, reference, &receipt, builder)
}

fn require_pending_state(matrix: &Matrix) -> Result<()> {
    if matrix.runtime_receipt.is_some()
        || matrix.version_independence.status != "pending"
        || matrix
            .platform_smoke
            .iter()
            .any(|row| row.status != "pending")
    {
        bail!(
            "a null runtime_receipt requires pending version independence and all five pending platform smokes"
        );
    }
    Ok(())
}

fn require_green_state(matrix: &Matrix) -> Result<()> {
    if matrix.version_independence.status != "green"
        || matrix
            .platform_smoke
            .iter()
            .any(|row| row.status != "green")
    {
        bail!(
            "a runtime_receipt requires green version independence and all five green platform smokes"
        );
    }
    Ok(())
}

fn validate_builder_reference(builder: &BuilderRef) -> Result<()> {
    if builder.path != BUILDER_WORKFLOW {
        bail!("runtime_builder is not bound to the protected reusable workflow");
    }
    validate_sha(&builder.commit, 40, "runtime_builder commit")
}

fn validate_reference_shape(reference: &ReceiptRef) -> Result<(u64, u64)> {
    validate_sha(&reference.sha256, 64, "runtime receipt sha256")?;
    validate_sha(
        &reference.attestation_sha256,
        64,
        "runtime receipt attestation sha256",
    )?;
    if reference.path == reference.attestation_path {
        bail!("runtime receipt and attestation paths must be distinct");
    }
    let identity = canonical_run_identity(&reference.path, ".json")?;
    let attestation_identity =
        canonical_run_identity(&reference.attestation_path, ".sigstore.json")?;
    if identity != attestation_identity {
        bail!("runtime receipt and attestation filenames must share one run id and attempt");
    }
    Ok(identity)
}

fn canonical_run_identity(path: &str, suffix: &str) -> Result<(u64, u64)> {
    if !path.starts_with(RECEIPT_DIRECTORY) {
        bail!("runtime receipt evidence must be under `{RECEIPT_DIRECTORY}`");
    }
    let stem = path
        .strip_prefix(RECEIPT_PREFIX)
        .and_then(|rest| rest.strip_suffix(suffix))
        .context("runtime receipt evidence filename is not canonical")?;
    let (run_digits, attempt_digits) = stem
        .split_once("-attempt-")
        .context("runtime receipt evidence filename lacks its run attempt")?;
    let run_id = run_digits
        .parse::<u64>()
        .context("runtime receipt filename run id is not a positive integer")?;
    let attempt = attempt_digits
        .parse::<u64>()
        .context("runtime receipt filename attempt is not a positive integer")?;
    if run_id == 0
        || attempt == 0
        || run_digits != run_id.to_string()
        || attempt_digits != attempt.to_string()
    {
        bail!("runtime receipt filename run id and attempt must be canonical and positive");
    }
    Ok((run_id, attempt))
}

fn validate_digest(source: &[u8], expected: &str, label: &str) -> Result<()> {
    validate_sha(expected, 64, &format!("{label} sha256"))?;
    let actual = format!("{:x}", Sha256::digest(source));
    if expected != actual {
        bail!("{label} sha256 does not match its bytes");
    }
    Ok(())
}

fn parse_receipt(source: &[u8]) -> Result<RuntimeReceipt> {
    let value = crate::schema_compat::parse_json_no_duplicates(source, "client runtime receipt")?;
    serde_json::from_value(value).context("invalid client runtime receipt")
}

fn validate_receipt(receipt: &RuntimeReceipt, builder: &BuilderRef) -> Result<()> {
    if receipt.schema_version != 1 || receipt.receipt_type != "client_runtime_receipt" {
        bail!("runtime receipt must use schema_version 1 and type `client_runtime_receipt`");
    }
    if receipt.repository.name != REPOSITORY || receipt.repository.id == 0 {
        bail!("runtime receipt repository identity is invalid");
    }
    validate_sha(&receipt.tested_commit, 40, "runtime receipt tested_commit")?;
    validate_sha(&receipt.tested_tree, 40, "runtime receipt tested_tree")?;
    validate_sha(
        &receipt.builder_workflow.commit,
        40,
        "runtime receipt builder workflow commit",
    )?;
    validate_sha(&receipt.run.head_sha, 40, "runtime receipt run head_sha")?;
    if receipt.tested_commit != receipt.run.head_sha {
        bail!("runtime receipt tested commit and run head SHA differ");
    }
    if receipt.builder_workflow.path != builder.path
        || receipt.builder_workflow.commit != builder.commit
    {
        bail!("runtime receipt does not match the pinned runtime_builder");
    }
    if receipt.builder_workflow.commit == receipt.tested_commit {
        bail!("runtime receipt builder must predate the tested source commit");
    }
    validate_run(&receipt.run)?;
    let jobs = validate_platforms(&receipt.platforms)?;
    validate_version_independence(&receipt.version_independence, &jobs)
}

fn validate_run(run: &Run) -> Result<()> {
    if run.id == 0 || run.attempt == 0 {
        bail!("runtime receipt run id and attempt must be positive");
    }
    if run.event != "workflow_dispatch"
        || run.head_branch != "main"
        || run.workflow_path != RELEASE_WORKFLOW
    {
        bail!("runtime receipt run is not the trusted main-branch release workflow dispatch");
    }
    let expected_url = format!("https://github.com/{REPOSITORY}/actions/runs/{}", run.id);
    if run.url != expected_url {
        bail!("runtime receipt run URL is not canonical");
    }
    Ok(())
}

fn validate_platforms(platforms: &[Platform]) -> Result<BTreeMap<&str, u64>> {
    let required = platform_contract();
    if platforms.len() != required.len() {
        bail!("runtime receipt must contain exactly five native platforms");
    }
    if platforms
        .iter()
        .map(|platform| platform.platform.as_str())
        .ne(PLATFORM_ORDER)
    {
        bail!("runtime receipt native platforms are not in canonical order");
    }
    let mut jobs = BTreeMap::new();
    let mut job_ids = BTreeSet::new();
    let mut runner_ids = BTreeSet::new();
    for platform in platforms {
        let Some(&(target, runner, version_step)) = required.get(platform.platform.as_str()) else {
            bail!(
                "runtime receipt has unexpected platform `{}`",
                platform.platform
            );
        };
        if platform.target != target || platform.runner != runner {
            bail!(
                "runtime receipt platform `{}` has the wrong target or runner",
                platform.platform
            );
        }
        if jobs
            .insert(platform.platform.as_str(), platform.job.id)
            .is_some()
        {
            bail!(
                "runtime receipt platform `{}` is duplicated",
                platform.platform
            );
        }
        if platform.job.id == 0
            || platform.job.runner_id == 0
            || !job_ids.insert(platform.job.id)
            || !runner_ids.insert(platform.job.runner_id)
        {
            bail!("runtime receipt platform job ids and runner ids must be positive and unique");
        }
        let expected_runner_name = format!("GitHub Actions {}", platform.job.runner_id);
        if platform.job.runner_name != expected_runner_name
            || platform.job.runner_group_id != 0
            || platform.job.runner_group_name != "GitHub Actions"
            || platform.job.labels.as_slice() != [runner]
            || platform.job.conclusion != "success"
        {
            bail!(
                "runtime receipt platform `{}` is not a successful GitHub-hosted runner job",
                platform.platform
            );
        }
        if platform.steps.target_tests != "success"
            || platform.steps.binary_build != "success"
            || platform.steps.binary_identity != "success"
            || platform.steps.native_client_smoke != "success"
            || platform.steps.version_independence != version_step
        {
            bail!(
                "runtime receipt platform `{}` lacks the required successful native steps",
                platform.platform
            );
        }
    }
    if jobs.keys().copied().collect::<BTreeSet<_>>()
        != required.keys().copied().collect::<BTreeSet<_>>()
    {
        bail!("runtime receipt native platform set is incomplete");
    }
    Ok(jobs)
}

fn validate_version_independence(
    versions: &[VersionIndependence],
    jobs: &BTreeMap<&str, u64>,
) -> Result<()> {
    let required = BTreeMap::from([("unix", "linux-x86_64"), ("windows-msvc", "windows-x86_64")]);
    if versions.len() != required.len() {
        bail!("runtime receipt must contain exactly Unix and Windows version-independence runs");
    }
    if versions
        .iter()
        .map(|version| version.operating_system.as_str())
        .ne(VERSION_ORDER)
    {
        bail!("runtime receipt version-independence runs are not in canonical order");
    }
    let mut actual = BTreeSet::new();
    for version in versions {
        let Some(platform) = required.get(version.operating_system.as_str()) else {
            bail!(
                "runtime receipt has unexpected version-independence OS `{}`",
                version.operating_system
            );
        };
        if !actual.insert(version.operating_system.as_str())
            || version.platform != *platform
            || jobs.get(platform).copied() != Some(version.job_id)
            || version.clients.as_slice() != ["headless", "one-shot", "tui"]
            || version.conclusion != "success"
        {
            bail!(
                "runtime receipt version-independence run `{}` is invalid",
                version.operating_system
            );
        }
    }
    Ok(())
}

fn platform_contract() -> BTreeMap<&'static str, (&'static str, &'static str, &'static str)> {
    BTreeMap::from([
        (
            "linux-arm64",
            ("aarch64-unknown-linux-musl", "ubuntu-24.04-arm", "skipped"),
        ),
        (
            "linux-x86_64",
            ("x86_64-unknown-linux-musl", "ubuntu-24.04", "success"),
        ),
        (
            "macos-arm64",
            ("aarch64-apple-darwin", "macos-15", "skipped"),
        ),
        (
            "macos-x86_64",
            ("x86_64-apple-darwin", "macos-15-intel", "skipped"),
        ),
        (
            "windows-x86_64",
            ("x86_64-pc-windows-msvc", "windows-2022", "success"),
        ),
    ])
}

fn validate_sha(value: &str, length: usize, label: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be exactly {length} lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
