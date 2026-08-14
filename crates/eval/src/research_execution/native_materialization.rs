//! Strict v3 native-patch materialization and post-run consumption verification.

use super::{ExecutionSnapshot, read_file_bounded};
use crate::research_protocol::{
    MAX_NATIVE_MATERIALIZATION_BYTES, MAX_NATIVE_RECEIPT_BYTES, NATIVE_CONSUMPTION_SCHEMA,
    NATIVE_MATERIALIZATION_SCHEMA, NativeConsumptionReceipt, NativeMaterializationDocument,
    ResearchRunState, RunSpec,
};
use crate::strict_json::parse_json_no_duplicates;
use crate::terminal_bench::ArtifactReference;
use crate::tuner::{CandidateMaterialization, CandidatePatch};
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
        {
            return Err("native materialization identity changed".into());
        }
        Ok(document)
    }
}

pub(crate) fn materialize_native_patches(
    candidate_sha256: &str,
    materialization: &CandidateMaterialization,
    destination: &str,
) -> Result<MaterializedNativePatches, String> {
    if !materialization.has_native_patches() {
        return Err("empty native materialization is forbidden".into());
    }
    let document = NativeMaterializationDocument {
        schema_id: NATIVE_MATERIALIZATION_SCHEMA.into(),
        candidate_sha256: candidate_sha256.into(),
        candidate_graph_identity: materialization
            .graph_identity()
            .map_err(|error| error.to_string())?,
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
    })
}

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
    let correlated = document.schema_id == NATIVE_MATERIALIZATION_SCHEMA
        && document.candidate_sha256 == spec.candidate_sha256
        && document.candidate_graph_identity == spec.candidate_graph_identity
        && receipt.schema_id == NATIVE_CONSUMPTION_SCHEMA
        && receipt.candidate_sha256 == spec.candidate_sha256
        && receipt.materialization_sha256 == spec.candidate_graph_identity.materialization_sha256
        && receipt.experiment_sha256 == spec.candidate_graph_identity.experiment_sha256
        && receipt.topology_sha256 == spec.candidate_graph_identity.topology_sha256
        && receipt.native_materialization_sha256 == spec.native_materialization_sha256
        && receipt.run_id == spec.run_id
        && receipt.run_id == terminal_run_id
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
