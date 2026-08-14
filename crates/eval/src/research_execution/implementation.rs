use super::{ExecutionSnapshot, read_file_bounded};
use crate::research_protocol::{ResearchRunState, RunSpec};
use crate::strict_json::parse_json_no_duplicates;
use crate::terminal_bench::ArtifactReference;
use iteron_marketplace::{
    ImplementationActivation, ImplementationActivationDocument, MAX_IMPLEMENTATION_ACTIVATION_BYTES,
};
use iteron_protocol::capability_set::CapabilitySet;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const RECEIPT_SCHEMA: &str = "iteron-implementation-consumption/1";
const MAX_RECEIPT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumptionReceipt {
    schema_id: String,
    candidate_sha256: String,
    activation_sha256: String,
    cli_run_id: String,
    implementations: Vec<ImplementationLifecycle>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImplementationLifecycle {
    module: iteron_tunables::ModuleId,
    implementation_id: String,
    loaded: bool,
    started: bool,
    terminal: bool,
    stopped: bool,
}

pub(super) fn require_consumption(
    run: &RunSpec,
    mut snapshot: ExecutionSnapshot,
) -> ExecutionSnapshot {
    let (Some(activation_path), Some(expected_digest)) = (
        run.implementation_candidate_path(),
        run.implementation_candidate_digest(),
    ) else {
        return snapshot;
    };
    let checked = load_receipt(run, activation_path, expected_digest, &snapshot);
    match checked {
        Ok(artifact) => {
            let already_retained = snapshot.artifacts.iter().any(|item| item == &artifact);
            let evidence_bytes = snapshot
                .artifacts
                .iter()
                .map(|item| item.bytes)
                .sum::<u64>()
                .saturating_add(if already_retained { 0 } else { artifact.bytes });
            if evidence_bytes > run.max_evidence_bytes() {
                snapshot.state = ResearchRunState::EvidenceLimit;
                snapshot.terminal_result = None;
                snapshot.detail = Some("implementation evidence byte bound reached".into());
            } else if !already_retained {
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

pub(crate) fn receipt_path(run: &RunSpec) -> Option<PathBuf> {
    let digest = run.implementation_candidate_digest()?;
    Some(
        Path::new(run.runs_dir()).join(format!(".iteron-implementation-{digest}-consumption.json")),
    )
}

fn load_receipt(
    run: &RunSpec,
    activation_path: &str,
    expected_digest: &str,
    snapshot: &ExecutionSnapshot,
) -> Result<ArtifactReference, String> {
    let activation_bytes = read_file_bounded(
        Path::new(activation_path),
        MAX_IMPLEMENTATION_ACTIVATION_BYTES as u64,
    )
    .map_err(|_| "implementation activation disappeared before result validation".to_owned())?;
    if hex::encode(Sha256::digest(&activation_bytes)) != expected_digest {
        return Err("implementation activation changed after candidate validation".into());
    }
    let activation = ImplementationActivation::from_json(&activation_bytes, CapabilitySet::none())
        .map_err(|_| "implementation activation no longer validates".to_owned())?;
    let document: ImplementationActivationDocument = serde_json::from_slice(&activation_bytes)
        .map_err(|_| "implementation activation document is malformed".to_owned())?;
    let path = receipt_path(run)
        .ok_or_else(|| "implementation consumption receipt path is unavailable".to_owned())?;
    let bytes = read_file_bounded(&path, MAX_RECEIPT_BYTES)
        .map_err(|_| "implementation process exited without consumption evidence".to_owned())?;
    let value = parse_json_no_duplicates(&bytes)
        .map_err(|_| "implementation consumption evidence is not strict JSON".to_owned())?;
    let receipt: ConsumptionReceipt = serde_json::from_value(value)
        .map_err(|_| "implementation consumption evidence has the wrong schema".to_owned())?;
    let run_id = snapshot
        .terminal_result
        .as_ref()
        .map(|result| result.run_id.as_str())
        .ok_or_else(|| "implementation consumption evidence has no terminal run".to_owned())?;
    let exact = receipt.schema_id == RECEIPT_SCHEMA
        && receipt.candidate_sha256 == document.candidate_sha256
        && receipt.activation_sha256 == expected_digest
        && receipt.cli_run_id == run_id
        && receipt.implementations.len() == activation.len()
        && activation
            .plans()
            .zip(&receipt.implementations)
            .all(|((module, plan), item)| {
                item.module == module
                    && item.implementation_id == plan.implementation_id()
                    && item.loaded
                    && item.started
                    && item.terminal
                    && item.stopped
            });
    if !exact {
        return Err("implementation consumption evidence failed exact correlation".into());
    }
    Ok(ArtifactReference {
        path: path.to_string_lossy().into_owned(),
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}
