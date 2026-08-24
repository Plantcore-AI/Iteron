//! Strict v3 native-patch materialization and post-run consumption verification.

#[cfg(unix)]
use super::ExecutionSnapshot;
use super::read_file_bounded;
use crate::research_protocol::{
    MAX_NATIVE_MATERIALIZATION_BYTES, NATIVE_MATERIALIZATION_SCHEMA, NativeMaterializationDocument,
};
#[cfg(unix)]
use crate::research_protocol::{
    MAX_NATIVE_RECEIPT_BYTES, NATIVE_CONSUMPTION_SCHEMA, NativeConsumptionReceipt,
    ResearchRunState, RunSpec,
};
use crate::strict_json::parse_json_no_duplicates;
#[cfg(unix)]
use crate::terminal_bench::ArtifactReference;
use crate::tuner::CandidateMaterialization;
#[cfg(unix)]
use crate::tuner::{CandidateExecutionNode, CandidateImplementation, CandidatePatch};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Component, Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaterializedNativePatches {
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
    pub(crate) patch_count: u64,
    pub(crate) node_count: u64,
    pub(crate) implementation_count: u64,
}

impl MaterializedNativePatches {
    pub(crate) fn verify(&self) -> Result<NativeMaterializationDocument, String> {
        let path = Path::new(&self.path);
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "native materialization is no longer readable".to_owned())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != self.bytes
            || self.bytes > MAX_NATIVE_MATERIALIZATION_BYTES as u64
        {
            return Err("native materialization file identity changed".into());
        }
        let bytes = read_file_bounded(path, MAX_NATIVE_MATERIALIZATION_BYTES as u64)
            .map_err(|_| "native materialization is no longer bounded".to_owned())?;
        if hex::encode(Sha256::digest(&bytes)) != self.sha256 {
            return Err("native materialization digest changed".into());
        }
        let value = parse_json_no_duplicates(&bytes)
            .map_err(|_| "native materialization is not strict JSON".to_owned())?;
        let document: NativeMaterializationDocument = serde_json::from_value(value)
            .map_err(|_| "native materialization has the wrong schema".to_owned())?;
        if document.schema_id != NATIVE_MATERIALIZATION_SCHEMA
            || patch_count(&document) != self.patch_count
            || document.production_plan.nodes.len() as u64 != self.node_count
            || document.production_plan.implementations.len() as u64 != self.implementation_count
        {
            return Err("native materialization identity changed".into());
        }
        Ok(document)
    }
}

pub(crate) fn materialize_native_patches(
    candidate_sha256: &str,
    materialization: &CandidateMaterialization,
    implementation_activation_sha256: Option<&str>,
    destination: &str,
) -> Result<MaterializedNativePatches, String> {
    if !materialization.has_native_patches() {
        return Err("empty native materialization is forbidden".into());
    }
    let production_plan = materialization
        .production_plan()
        .map_err(|error| error.to_string())?;
    let document = NativeMaterializationDocument {
        schema_id: NATIVE_MATERIALIZATION_SCHEMA.into(),
        candidate_sha256: candidate_sha256.into(),
        candidate_graph_identity: materialization
            .graph_identity()
            .map_err(|error| error.to_string())?,
        implementation_activation_sha256: implementation_activation_sha256.map(str::to_owned),
        production_plan,
        direct_config_patches: materialization.direct_config_patches.clone(),
        caller_input_patches: materialization.caller_input_patches.clone(),
    };
    let bytes = serde_json::to_vec(&document).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_NATIVE_MATERIALIZATION_BYTES {
        return Err("native materialization exceeds its byte bound".into());
    }
    create_new_nofollow(Path::new(destination), &bytes)?;
    Ok(MaterializedNativePatches {
        path: destination.into(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        bytes: bytes.len() as u64,
        patch_count: patch_count(&document),
        node_count: document.production_plan.nodes.len() as u64,
        implementation_count: document.production_plan.implementations.len() as u64,
    })
}

#[cfg(unix)]
pub(super) fn require_native_consumption(
    run: &RunSpec,
    mut snapshot: ExecutionSnapshot,
) -> ExecutionSnapshot {
    let RunSpec::ExternalNative { spec } = run else {
        return snapshot;
    };
    if snapshot.state != ResearchRunState::Completed {
        return snapshot;
    }
    match validate_receipt(spec, &snapshot) {
        Ok(artifact) => {
            let total = snapshot
                .artifacts
                .iter()
                .map(|item| item.bytes)
                .sum::<u64>()
                .saturating_add(artifact.bytes);
            if total > spec.max_evidence_bytes {
                snapshot.state = ResearchRunState::EvidenceLimit;
                snapshot.terminal_result = None;
                snapshot.detail = Some("native consumption evidence byte bound reached".into());
            } else {
                snapshot.artifacts.push(artifact);
            }
        }
        Err(detail) => {
            snapshot.state = ResearchRunState::Failed;
            snapshot.terminal_result = None;
            snapshot.detail = Some(detail);
        }
    }
    snapshot
}

#[cfg(unix)]
fn validate_receipt(
    spec: &crate::research_protocol::ExternalNativeRunSpec,
    snapshot: &ExecutionSnapshot,
) -> Result<ArtifactReference, String> {
    let effective = read_file_bounded(
        Path::new(&spec.effective_profile_path),
        iteron_tunables::MAX_PROFILE_BYTES as u64,
    )
    .map_err(|_| "native adapter did not produce a bounded effective profile".to_owned())?;
    if hex::encode(Sha256::digest(&effective)) != spec.profile_sha256 {
        return Err("native adapter effective profile changed candidate identity".into());
    }
    let materialization_bytes = read_file_bounded(
        Path::new(&spec.native_materialization_path),
        MAX_NATIVE_MATERIALIZATION_BYTES as u64,
    )
    .map_err(|_| "native materialization disappeared before receipt validation".to_owned())?;
    if hex::encode(Sha256::digest(&materialization_bytes)) != spec.native_materialization_sha256 {
        return Err("native materialization changed after candidate validation".into());
    }
    let value = parse_json_no_duplicates(&materialization_bytes)
        .map_err(|_| "native materialization is not strict JSON".to_owned())?;
    let document: NativeMaterializationDocument = serde_json::from_value(value)
        .map_err(|_| "native materialization has the wrong schema".to_owned())?;
    let receipt_bytes = read_file_bounded(
        Path::new(&spec.consumption_receipt_path),
        MAX_NATIVE_RECEIPT_BYTES as u64,
    )
    .map_err(|_| "native adapter exited without consumption evidence".to_owned())?;
    let value = parse_json_no_duplicates(&receipt_bytes)
        .map_err(|_| "native consumption evidence is not strict JSON".to_owned())?;
    let receipt: NativeConsumptionReceipt = serde_json::from_value(value)
        .map_err(|_| "native consumption evidence has the wrong schema".to_owned())?;
    let terminal_run_id = snapshot
        .terminal_result
        .as_ref()
        .map(|result| result.run_id.as_str())
        .ok_or_else(|| "native consumption evidence has no terminal run".to_owned())?;
    let patches = document
        .direct_config_patches
        .iter()
        .chain(&document.caller_input_patches)
        .collect::<Vec<_>>();
    let activation_correlated = match (
        document.implementation_activation_sha256.as_deref(),
        receipt.implementation_activation_sha256.as_deref(),
    ) {
        (None, None) => document.production_plan.implementations.is_empty(),
        (Some(expected), Some(observed)) => {
            expected == observed
                && valid_raw_digest(expected)
                && !document.production_plan.implementations.is_empty()
        }
        _ => false,
    };
    let correlated = document.schema_id == NATIVE_MATERIALIZATION_SCHEMA
        && document.candidate_sha256 == spec.candidate_sha256
        && document.candidate_graph_identity == spec.candidate_graph_identity
        && receipt.schema_id == NATIVE_CONSUMPTION_SCHEMA
        && receipt.candidate_sha256 == spec.candidate_sha256
        && receipt.materialization_sha256 == spec.candidate_graph_identity.materialization_sha256
        && receipt.experiment_sha256 == spec.candidate_graph_identity.experiment_sha256
        && receipt.topology_sha256 == spec.candidate_graph_identity.topology_sha256
        && receipt.native_materialization_sha256 == spec.native_materialization_sha256
        && activation_correlated
        && receipt.run_id == spec.run_id
        && receipt.run_id == terminal_run_id
        && receipt.nodes.len() == document.production_plan.nodes.len()
        && document
            .production_plan
            .nodes
            .iter()
            .zip(&receipt.nodes)
            .all(|(expected, observed)| node_consumed(expected, observed))
        && receipt.implementations.len() == document.production_plan.implementations.len()
        && document
            .production_plan
            .implementations
            .iter()
            .zip(&receipt.implementations)
            .all(|(expected, observed)| implementation_consumed(expected, observed))
        && receipt.patches.len() == patches.len()
        && patches
            .iter()
            .zip(&receipt.patches)
            .all(|(expected, observed)| patch_consumed(expected, observed));
    if !correlated {
        return Err("native consumption evidence failed exact correlation".into());
    }
    Ok(ArtifactReference {
        path: spec.consumption_receipt_path.clone(),
        bytes: receipt_bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&receipt_bytes)),
    })
}

#[cfg(unix)]
fn node_consumed(
    expected: &CandidateExecutionNode,
    observed: &crate::research_protocol::NativeNodeConsumption,
) -> bool {
    let digest = canonical_prefixed_digest(expected);
    observed.ordinal == expected.ordinal
        && observed.address == *expected.dimension.address()
        && observed.class == expected.class
        && digest.as_deref() == Some(observed.input_node_sha256.as_str())
        && observed.input_node_sha256 == observed.observed_node_sha256
        && observed.dependencies_loaded
        && observed.conditions_satisfied
        && observed.loaded
        && observed.applied
        && observed.observed
}

#[cfg(unix)]
fn implementation_consumed(
    expected: &CandidateImplementation,
    observed: &crate::research_protocol::NativeImplementationConsumption,
) -> bool {
    let digest = canonical_prefixed_digest(expected);
    observed.module == expected.module
        && observed.implementation_id == expected.implementation_id
        && digest.as_deref() == Some(observed.input_binding_sha256.as_str())
        && observed.input_binding_sha256 == observed.observed_binding_sha256
        && observed.loaded
        && observed.applied
        && observed.observed
        && observed.started
        && observed.terminal
        && observed.stopped
}

#[cfg(unix)]
fn patch_consumed(
    expected: &CandidatePatch,
    observed: &crate::research_protocol::NativePatchConsumption,
) -> bool {
    let digest = serde_json::to_vec(&expected.value)
        .ok()
        .map(|bytes| format!("sha256:{}", hex::encode(Sha256::digest(bytes))));
    observed.address == expected.address
        && digest.as_deref() == Some(observed.input_value_sha256.as_str())
        && observed.input_value_sha256 == observed.observed_value_sha256
        && observed.loaded
        && observed.applied
        && observed.observed
}

#[cfg(unix)]
fn canonical_prefixed_digest(value: &impl serde::Serialize) -> Option<String> {
    serde_json::to_vec(value)
        .ok()
        .map(|bytes| format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(unix)]
fn valid_raw_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn patch_count(document: &NativeMaterializationDocument) -> u64 {
    document
        .direct_config_patches
        .len()
        .saturating_add(document.caller_input_patches.len()) as u64
}

fn create_new_nofollow(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("native materialization destination is not absolute".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "native materialization destination has no parent".to_owned())?;
    let mut prefix = std::path::PathBuf::new();
    for component in parent.components() {
        prefix.push(component.as_os_str());
        if matches!(component, Component::RootDir) {
            continue;
        }
        if std::fs::symlink_metadata(&prefix)
            .map_err(|_| "native materialization parent is unavailable".to_owned())?
            .file_type()
            .is_symlink()
        {
            return Err("native materialization parent contains a symlink".into());
        }
    }
    if parent
        .canonicalize()
        .map_err(|_| "native materialization parent is unavailable")?
        != parent
    {
        return Err("native materialization parent is not canonical".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_| "native materialization destination is not create-new".to_owned())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "native materialization could not be written exactly".to_owned())
}
