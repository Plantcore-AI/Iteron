//! Bounded loading and explicit N-1 migration for persisted evolution contracts.
//!
//! Direct Serde derives remain public for source compatibility and in-memory composition. Code
//! loading persisted JSON should use `PolicyManifest::load_json` or
//! `TrajectoryEnvelope::load_json`: those entry points inspect the schema before decoding the
//! current contract, migrate exactly N-1, and reject every unknown version.

use crate::{
    ArtifactKind, ContractError, DataGovernance, EVOLUTION_SCHEMA_VERSION, EvolutionMethod,
    PolicyBundle, PolicyManifest, PolicyRef, ProtocolRange, RewardVector, StrategyDecision,
    TrajectoryEnvelope,
};
use core_protocol::{Capability, RunId, TenantId};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;

pub const EVOLUTION_PREVIOUS_SCHEMA_VERSION: u16 = 1;
pub const MAX_POLICY_MANIFEST_JSON_BYTES: usize = 256 * 1024;
pub const MAX_TRAJECTORY_JSON_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvolutionDocumentKind {
    PolicyManifest,
    Trajectory,
}

impl std::fmt::Display for EvolutionDocumentKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyManifest => formatter.write_str("policy manifest"),
            Self::Trajectory => formatter.write_str("trajectory"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EvolutionLoadError {
    #[error("{document} JSON is {actual} bytes; load limit is {limit}")]
    DocumentTooLarge {
        document: EvolutionDocumentKind,
        limit: usize,
        actual: usize,
    },
    #[error("{document} JSON could not be decoded: {source}")]
    InvalidJson {
        document: EvolutionDocumentKind,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "{document} schema {found} is newer than supported schema {current}; refusing future data"
    )]
    FutureSchema {
        document: EvolutionDocumentKind,
        found: u16,
        current: u16,
    },
    #[error(
        "{document} schema {found} is unsupported; oldest supported schema is {oldest_supported}"
    )]
    UnsupportedSchema {
        document: EvolutionDocumentKind,
        found: u16,
        oldest_supported: u16,
    },
    #[error("{document} contract is invalid after loading/migration: {source}")]
    InvalidContract {
        document: EvolutionDocumentKind,
        #[source]
        source: ContractError,
    },
}

#[derive(Deserialize)]
struct SchemaHeader {
    schema_version: u16,
}

fn schema_version(
    bytes: &[u8],
    document: EvolutionDocumentKind,
    limit: usize,
) -> Result<u16, EvolutionLoadError> {
    if bytes.len() > limit {
        return Err(EvolutionLoadError::DocumentTooLarge {
            document,
            limit,
            actual: bytes.len(),
        });
    }
    decode_json::<SchemaHeader>(bytes, document).map(|header| header.schema_version)
}

fn decode_json<T: DeserializeOwned>(
    bytes: &[u8],
    document: EvolutionDocumentKind,
) -> Result<T, EvolutionLoadError> {
    serde_json::from_slice(bytes)
        .map_err(|source| EvolutionLoadError::InvalidJson { document, source })
}

fn validate_manifest(manifest: PolicyManifest) -> Result<PolicyManifest, EvolutionLoadError> {
    manifest
        .validate()
        .map_err(|source| EvolutionLoadError::InvalidContract {
            document: EvolutionDocumentKind::PolicyManifest,
            source,
        })?;
    Ok(manifest)
}

fn validate_trajectory(
    trajectory: TrajectoryEnvelope,
) -> Result<TrajectoryEnvelope, EvolutionLoadError> {
    trajectory
        .validate()
        .map_err(|source| EvolutionLoadError::InvalidContract {
            document: EvolutionDocumentKind::Trajectory,
            source,
        })?;
    Ok(trajectory)
}

impl PolicyManifest {
    /// Load bounded persisted JSON, migrating schema N-1 and rejecting every other version.
    pub fn load_json(bytes: &[u8]) -> Result<Self, EvolutionLoadError> {
        let document = EvolutionDocumentKind::PolicyManifest;
        match schema_version(bytes, document, MAX_POLICY_MANIFEST_JSON_BYTES)? {
            EVOLUTION_SCHEMA_VERSION => validate_manifest(decode_json(bytes, document)?),
            EVOLUTION_PREVIOUS_SCHEMA_VERSION => {
                let legacy: PolicyManifestV1 = decode_json(bytes, document)?;
                validate_manifest(migrate_policy_manifest_v1(legacy))
            }
            found if found > EVOLUTION_SCHEMA_VERSION => Err(EvolutionLoadError::FutureSchema {
                document,
                found,
                current: EVOLUTION_SCHEMA_VERSION,
            }),
            found => Err(EvolutionLoadError::UnsupportedSchema {
                document,
                found,
                oldest_supported: EVOLUTION_PREVIOUS_SCHEMA_VERSION,
            }),
        }
    }
}

impl TrajectoryEnvelope {
    /// Load bounded persisted JSON, migrating schema N-1 and rejecting every other version.
    pub fn load_json(bytes: &[u8]) -> Result<Self, EvolutionLoadError> {
        let document = EvolutionDocumentKind::Trajectory;
        match schema_version(bytes, document, MAX_TRAJECTORY_JSON_BYTES)? {
            EVOLUTION_SCHEMA_VERSION => validate_trajectory(decode_json(bytes, document)?),
            EVOLUTION_PREVIOUS_SCHEMA_VERSION => {
                let legacy: TrajectoryEnvelopeV1 = decode_json(bytes, document)?;
                validate_trajectory(migrate_trajectory_v1(legacy))
            }
            found if found > EVOLUTION_SCHEMA_VERSION => Err(EvolutionLoadError::FutureSchema {
                document,
                found,
                current: EVOLUTION_SCHEMA_VERSION,
            }),
            found => Err(EvolutionLoadError::UnsupportedSchema {
                document,
                found,
                oldest_supported: EVOLUTION_PREVIOUS_SCHEMA_VERSION,
            }),
        }
    }
}

#[derive(Deserialize)]
struct PolicyManifestV1 {
    schema_version: u16,
    policy: PolicyRef,
    artifact_kind: ArtifactKind,
    artifact_locator: String,
    parent: Option<PolicyRef>,
    method: EvolutionMethod,
    protocol: ProtocolRange,
    required_capabilities: BTreeSet<Capability>,
    training_dataset_digest: Option<String>,
    evaluation_suite_digest: String,
}

fn migrate_policy_manifest_v1(legacy: PolicyManifestV1) -> PolicyManifest {
    debug_assert_eq!(legacy.schema_version, EVOLUTION_PREVIOUS_SCHEMA_VERSION);
    PolicyManifest {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        policy: legacy.policy,
        artifact_kind: legacy.artifact_kind,
        artifact_locator: legacy.artifact_locator,
        parent: legacy.parent,
        method: legacy.method,
        protocol: legacy.protocol,
        required_capabilities: legacy.required_capabilities,
        training_dataset_digest: legacy.training_dataset_digest,
        evaluation_suite_digest: legacy.evaluation_suite_digest,
    }
}

#[derive(Deserialize)]
struct TrajectoryEnvelopeV1 {
    schema_version: u16,
    run_id: RunId,
    tenant_id: TenantId,
    task_id: String,
    domain: String,
    environment_digest: String,
    bundle: PolicyBundle,
    decisions: Vec<StrategyDecision>,
    terminal_outcome: String,
    reward: RewardVector,
    governance: DataGovernance,
}

fn migrate_trajectory_v1(legacy: TrajectoryEnvelopeV1) -> TrajectoryEnvelope {
    debug_assert_eq!(legacy.schema_version, EVOLUTION_PREVIOUS_SCHEMA_VERSION);
    TrajectoryEnvelope {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        run_id: legacy.run_id,
        tenant_id: legacy.tenant_id,
        task_id: legacy.task_id,
        domain: legacy.domain,
        environment_digest: legacy.environment_digest,
        bundle: legacy.bundle,
        decisions: legacy.decisions,
        terminal_outcome: legacy.terminal_outcome,
        reward: legacy.reward,
        governance: legacy.governance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST_V1: &[u8] = include_bytes!("../tests/fixtures/policy-manifest-v1.json");
    const TRAJECTORY_V1: &[u8] = include_bytes!("../tests/fixtures/trajectory-v1.json");

    #[test]
    fn schema_v1_fixtures_migrate_and_round_trip_as_current() {
        let manifest = PolicyManifest::load_json(MANIFEST_V1).unwrap();
        assert_eq!(manifest.schema_version, EVOLUTION_SCHEMA_VERSION);
        let manifest_current = serde_json::to_vec(&manifest).unwrap();
        assert_eq!(
            PolicyManifest::load_json(&manifest_current).unwrap(),
            manifest
        );

        let trajectory = TrajectoryEnvelope::load_json(TRAJECTORY_V1).unwrap();
        assert_eq!(trajectory.schema_version, EVOLUTION_SCHEMA_VERSION);
        let trajectory_current = serde_json::to_vec(&trajectory).unwrap();
        assert_eq!(
            TrajectoryEnvelope::load_json(&trajectory_current).unwrap(),
            trajectory
        );
    }

    #[test]
    fn future_schema_is_typed_and_fail_closed_before_current_decode() {
        let future = EVOLUTION_SCHEMA_VERSION + 1;
        let minimal_future = format!(r#"{{"schema_version":{future}}}"#);

        assert!(matches!(
            PolicyManifest::load_json(minimal_future.as_bytes()),
            Err(EvolutionLoadError::FutureSchema {
                document: EvolutionDocumentKind::PolicyManifest,
                found,
                current: EVOLUTION_SCHEMA_VERSION,
            }) if found == future
        ));
        assert!(matches!(
            TrajectoryEnvelope::load_json(minimal_future.as_bytes()),
            Err(EvolutionLoadError::FutureSchema {
                document: EvolutionDocumentKind::Trajectory,
                found,
                current: EVOLUTION_SCHEMA_VERSION,
            }) if found == future
        ));
    }

    #[test]
    fn manifest_loader_rejects_oversized_input_before_deserialization() {
        let oversized = vec![b' '; MAX_POLICY_MANIFEST_JSON_BYTES + 1];
        assert!(matches!(
            PolicyManifest::load_json(&oversized),
            Err(EvolutionLoadError::DocumentTooLarge {
                document: EvolutionDocumentKind::PolicyManifest,
                limit: MAX_POLICY_MANIFEST_JSON_BYTES,
                actual,
            }) if actual == oversized.len()
        ));
    }
}
