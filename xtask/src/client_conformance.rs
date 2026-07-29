use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

mod runtime_receipt;

const MATRIX_PATH: &str = "governance/client-conformance.json";
const MAX_MATRIX_BYTES: u64 = 256 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EVIDENCE_ITEMS: usize = 64;
const REQUIRED_CAPABILITIES: [&str; 8] = [
    "machine_output_contract",
    "streaming_render",
    "osc8_links",
    "notifications",
    "image_input",
    "reconnect_resume",
    "versioned_handshake",
    "bounded_backpressure",
];
const REQUIRED_CLIENTS: [&str; 3] = ["headless", "one-shot", "tui"];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Matrix {
    schema_version: u32,
    placement_reference: String,
    runtime_builder: Option<BuilderRef>,
    runtime_receipt: Option<ReceiptRef>,
    rows: Vec<CapabilityRow>,
    client_parity: ClientParity,
    version_independence: VersionIndependence,
    platform_smoke: Vec<PlatformSmoke>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct BuilderRef {
    path: String,
    commit: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReceiptRef {
    path: String,
    sha256: String,
    attestation_path: String,
    attestation_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CapabilityRow {
    capability: String,
    placement: String,
    status: String,
    clients: Vec<String>,
    evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Evidence {
    kind: String,
    path: String,
    selector: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ClientParity {
    status: String,
    clients: Vec<String>,
    transcript: String,
    test: Evidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct VersionIndependence {
    status: String,
    clients: Vec<String>,
    operating_systems: Vec<String>,
    evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PlatformSmoke {
    platform: String,
    target: String,
    runner: String,
    status: String,
    native: bool,
    workflow: Evidence,
}

pub(crate) fn validate(
    root: &Path,
    result_authority: &crate::schema_compat::CurrentCliResultSnapshot,
) -> Result<()> {
    let source = read_bounded_regular(root, MATRIX_PATH, MAX_MATRIX_BYTES)?;
    let matrix = parse_matrix(&source, "client conformance matrix")?;
    if matrix.schema_version != 2 {
        bail!("client conformance matrix schema_version must be 2");
    }
    if matrix.placement_reference != "docs/spec/capability-mapping.md#71-三个安置类别与一个前端平面"
    {
        bail!("client conformance matrix must bind capability placement to §7.1");
    }

    validate_capability_rows(root, &matrix.rows)?;
    validate_client_parity(root, &matrix.client_parity, result_authority)?;
    validate_version_independence(root, &matrix.version_independence)?;
    validate_platform_smoke(root, &matrix.platform_smoke)?;
    runtime_receipt::validate(root, &matrix)
}

fn parse_matrix(source: &[u8], label: &str) -> Result<Matrix> {
    let value = crate::schema_compat::parse_json_no_duplicates(source, label)?;
    if !value.as_object().is_some_and(|object| {
        object.contains_key("runtime_builder") && object.contains_key("runtime_receipt")
    }) {
        bail!("{label} must explicitly declare nullable runtime_builder and runtime_receipt");
    }
    serde_json::from_value(value).with_context(|| format!("invalid {label}"))
}

fn validate_capability_rows(root: &Path, rows: &[CapabilityRow]) -> Result<()> {
    if rows.len() != REQUIRED_CAPABILITIES.len() {
        bail!(
            "client conformance matrix must contain exactly {} capability rows",
            REQUIRED_CAPABILITIES.len()
        );
    }
    let mut actual = BTreeSet::new();
    for row in rows {
        if !actual.insert(row.capability.as_str()) {
            bail!(
                "client conformance capability `{}` is duplicated",
                row.capability
            );
        }
        require_green(&row.status, &format!("capability `{}`", row.capability))?;
        if row.placement != "D" {
            bail!(
                "client conformance capability `{}` must use placement D, not `{}`",
                row.capability,
                row.placement
            );
        }
        validate_clients(&row.clients, false)?;
        if row.evidence.is_empty() || row.evidence.len() > MAX_EVIDENCE_ITEMS {
            bail!(
                "client conformance capability `{}` must have 1..={MAX_EVIDENCE_ITEMS} evidence items",
                row.capability
            );
        }
        for evidence in &row.evidence {
            validate_evidence(root, evidence, &["test"])?;
        }
    }
    let required = REQUIRED_CAPABILITIES.into_iter().collect::<BTreeSet<_>>();
    if actual != required {
        bail!("client conformance capability rows differ: expected {required:?}, found {actual:?}");
    }
    Ok(())
}

fn validate_client_parity(
    root: &Path,
    parity: &ClientParity,
    result_authority: &crate::schema_compat::CurrentCliResultSnapshot,
) -> Result<()> {
    require_green(&parity.status, "three-client parity")?;
    validate_clients(&parity.clients, true)?;
    validate_evidence(root, &parity.test, &["test"])?;

    let source = read_bounded_regular(root, &parity.transcript, MAX_EVIDENCE_BYTES)?;
    let transcript =
        crate::schema_compat::parse_json_no_duplicates(&source, "three-client parity transcript")?;
    if transcript.get("schema_version").and_then(Value::as_u64) != Some(1) {
        bail!("three-client parity transcript schema_version must be 1");
    }
    if transcript
        .get("scripted_task")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        bail!("three-client parity transcript must name its scripted task");
    }
    let task_fixture = transcript
        .get("task_fixture")
        .and_then(Value::as_str)
        .context("three-client parity transcript lacks task_fixture")?;
    let task_source = read_bounded_regular(root, task_fixture, 64 * 1024)?;
    let task_text = std::str::from_utf8(&task_source)
        .context("three-client parity task fixture is not UTF-8")?
        .trim();
    if transcript.get("scripted_task").and_then(Value::as_str) != Some(task_text) {
        bail!("three-client parity transcript task differs from its fixture");
    }
    let expected_digest = transcript
        .get("task_fixture_sha256")
        .and_then(Value::as_str)
        .context("three-client parity transcript lacks task_fixture_sha256")?;
    let actual_digest = format!("{:x}", Sha256::digest(&task_source));
    if expected_digest != actual_digest {
        bail!("three-client parity task fixture digest does not match its transcript");
    }
    validate_process_smoke_references(root, &transcript)?;
    let clients = transcript
        .get("clients")
        .and_then(Value::as_array)
        .context("three-client parity transcript lacks clients")?;
    if clients.len() != REQUIRED_CLIENTS.len() {
        bail!("three-client parity transcript must contain exactly three client captures");
    }
    let mut names = BTreeSet::new();
    let mut reference: Option<&Value> = None;
    for client in clients {
        let name = client
            .get("client")
            .and_then(Value::as_str)
            .context("three-client parity capture lacks client")?;
        names.insert(name);
        let result = client
            .get("result")
            .context("three-client parity capture lacks result")?;
        result_authority
            .validate(result)
            .context("three-client parity result differs from canonical CLI authority")?;
        if let Some(reference) = reference {
            if result != reference {
                bail!("three-client parity results are not byte-structurally identical");
            }
        } else {
            reference = Some(result);
        }
    }
    let required = REQUIRED_CLIENTS.into_iter().collect::<BTreeSet<_>>();
    if names != required {
        bail!("three-client parity transcript clients differ: {names:?}");
    }
    Ok(())
}

fn validate_process_smoke_references(root: &Path, transcript: &Value) -> Result<()> {
    let references = transcript
        .get("process_smoke_references")
        .and_then(Value::as_array)
        .context("three-client parity transcript lacks process_smoke_references")?;
    if references.len() != REQUIRED_CLIENTS.len() {
        bail!("three-client parity transcript must name exactly three process smokes");
    }
    let mut clients = BTreeSet::new();
    for reference in references {
        let client = reference
            .get("client")
            .and_then(Value::as_str)
            .context("parity process smoke lacks client")?;
        let path = reference
            .get("path")
            .and_then(Value::as_str)
            .context("parity process smoke lacks path")?;
        let selector = reference
            .get("selector")
            .and_then(Value::as_str)
            .context("parity process smoke lacks selector")?;
        clients.insert(client);
        validate_evidence(
            root,
            &Evidence {
                kind: "test".into(),
                path: path.into(),
                selector: selector.into(),
            },
            &["test"],
        )?;
        let source = read_bounded_regular(root, path, MAX_EVIDENCE_BYTES)?;
        if !source
            .windows(b"fixtures/client-parity-task.txt".len())
            .any(|window| window == b"fixtures/client-parity-task.txt")
        {
            bail!("parity process smoke `{path}` is not pinned to the shared task fixture");
        }
    }
    let required = REQUIRED_CLIENTS.into_iter().collect::<BTreeSet<_>>();
    if clients != required {
        bail!("parity process smoke clients differ: {clients:?}");
    }
    Ok(())
}

fn validate_version_independence(root: &Path, version: &VersionIndependence) -> Result<()> {
    if !matches!(version.status.as_str(), "green" | "pending") {
        bail!("version independence status must be `green` or `pending`");
    }
    validate_clients(&version.clients, true)?;
    validate_exact_strings(
        &version.operating_systems,
        &["unix", "windows-msvc"],
        "version-independence operating systems",
    )?;
    if version.evidence.len() < 2 || version.evidence.len() > MAX_EVIDENCE_ITEMS {
        bail!("version independence must have 2..={MAX_EVIDENCE_ITEMS} executable tests");
    }
    for evidence in &version.evidence {
        validate_evidence(root, evidence, &["test"])?;
    }
    Ok(())
}

fn validate_platform_smoke(root: &Path, rows: &[PlatformSmoke]) -> Result<()> {
    let required = BTreeMap::from([
        (
            "linux-arm64",
            ("aarch64-unknown-linux-musl", "ubuntu-24.04-arm"),
        ),
        (
            "linux-x86_64",
            ("x86_64-unknown-linux-musl", "ubuntu-24.04"),
        ),
        ("macos-arm64", ("aarch64-apple-darwin", "macos-15")),
        ("macos-x86_64", ("x86_64-apple-darwin", "macos-15-intel")),
        ("windows-x86_64", ("x86_64-pc-windows-msvc", "windows-2022")),
    ]);
    if rows.len() != required.len() {
        bail!("platform smoke matrix must contain exactly five native rows");
    }
    let mut actual = BTreeSet::new();
    for row in rows {
        if !actual.insert(row.platform.as_str()) {
            bail!("platform smoke row `{}` is duplicated", row.platform);
        }
        let Some((target, runner)) = required.get(row.platform.as_str()) else {
            bail!("unexpected platform smoke row `{}`", row.platform);
        };
        if !matches!(row.status.as_str(), "green" | "pending") {
            bail!(
                "platform smoke `{}` status must be `green` or `pending`",
                row.platform
            );
        }
        if !row.native || row.target != *target || row.runner != *runner {
            bail!(
                "platform smoke `{}` must execute natively as {target} on {runner}",
                row.platform
            );
        }
        validate_evidence(root, &row.workflow, &["workflow"])?;
        if row.workflow.path != ".github/workflows/release.yml"
            || row.workflow.selector != row.target
        {
            bail!(
                "platform smoke `{}` must bind its native release workflow target",
                row.platform
            );
        }
    }
    let expected = required.keys().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("platform smoke rows differ: expected {expected:?}, found {actual:?}");
    }
    Ok(())
}

fn validate_clients(clients: &[String], require_all: bool) -> Result<()> {
    if clients.is_empty() || clients.len() > REQUIRED_CLIENTS.len() {
        bail!(
            "client list must contain 1..={} entries",
            REQUIRED_CLIENTS.len()
        );
    }
    let actual = clients.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if actual.len() != clients.len() {
        bail!("client list contains duplicates");
    }
    let required = REQUIRED_CLIENTS.into_iter().collect::<BTreeSet<_>>();
    if !actual.is_subset(&required) || (require_all && actual != required) {
        bail!("client list is not the required sibling-client set: {actual:?}");
    }
    Ok(())
}

fn validate_evidence(root: &Path, evidence: &Evidence, allowed: &[&str]) -> Result<()> {
    if evidence.kind == "target" || evidence.kind == "target-only" {
        bail!("target-only evidence is forbidden by the client conformance gate");
    }
    if !allowed.contains(&evidence.kind.as_str()) {
        bail!(
            "unsupported client conformance evidence kind `{}`; expected one of {allowed:?}",
            evidence.kind
        );
    }
    if evidence.selector.is_empty()
        || evidence.selector.len() > 512
        || evidence.selector.contains(['\n', '\r', '\0'])
    {
        bail!("client conformance evidence selector is invalid");
    }
    let source = read_bounded_regular(root, &evidence.path, MAX_EVIDENCE_BYTES)?;
    let text = std::str::from_utf8(&source)
        .with_context(|| format!("client evidence `{}` is not UTF-8", evidence.path))?;
    if !text.contains(&evidence.selector) {
        bail!(
            "client evidence `{}` lacks selector `{}`",
            evidence.path,
            evidence.selector
        );
    }
    Ok(())
}

fn validate_exact_strings(actual: &[String], expected: &[&str], label: &str) -> Result<()> {
    let actual_set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_set = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual.len() != actual_set.len() || actual_set != expected_set {
        bail!("{label} differs: expected {expected_set:?}, found {actual_set:?}");
    }
    Ok(())
}

fn require_green(status: &str, label: &str) -> Result<()> {
    if status != "green" {
        bail!("{label} is not green");
    }
    Ok(())
}

fn read_bounded_regular(root: &Path, relative: &str, max_bytes: u64) -> Result<Vec<u8>> {
    validate_repo_path(relative)?;
    let path = root.join(relative);
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("cannot inspect client conformance file `{relative}`"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("client conformance file `{relative}` must be a regular file");
    }
    if metadata.len() > max_bytes {
        bail!("client conformance file `{relative}` exceeds its {max_bytes}-byte limit");
    }
    std::fs::read(&path)
        .with_context(|| format!("cannot read client conformance file `{relative}`"))
}

fn validate_repo_path(relative: &str) -> Result<()> {
    if relative.is_empty()
        || relative.len() > 512
        || relative.contains(['\\', '\n', '\r', '\0'])
        || relative.contains("//")
    {
        bail!("invalid client conformance repository path `{relative}`");
    }
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("invalid client conformance repository path `{relative}`");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_only_capability_evidence_is_rejected() {
        let evidence = Evidence {
            kind: "target-only".into(),
            path: "Cargo.toml".into(),
            selector: "[workspace]".into(),
        };
        let error = validate_evidence(Path::new("."), &evidence, &["test"])
            .expect_err("target-only rows must fail")
            .to_string();
        assert!(error.contains("target-only"), "{error}");
    }

    #[test]
    fn generic_runtime_substring_evidence_is_not_a_capability_receipt() {
        let evidence = Evidence {
            kind: "runtime".into(),
            path: "Cargo.toml".into(),
            selector: "[workspace]".into(),
        };
        let error = validate_evidence(Path::new("."), &evidence, &["test"])
            .expect_err("runtime substring evidence must fail")
            .to_string();
        assert!(error.contains("unsupported"), "{error}");
    }
}
