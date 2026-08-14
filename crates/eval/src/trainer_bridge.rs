//! Method-neutral contracts shared by Iteron's native tuner and external optimizers.
//!
//! These records describe data, observations and resumable work. They do not select a winner,
//! activate a candidate, or grant a capability. All authority remains with the host that validates
//! and runs the candidate.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION: u16 = 1;
pub const TRAINER_BRIDGE_SCHEMA_VERSION: u16 = 2;
pub const MAX_TRAINER_BRIDGE_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_REWARD_OBJECTIVES: usize = 32;
pub const MAX_DISTRIBUTED_WORKERS: u16 = 256;
pub const MAX_BATCH_SUGGESTIONS: usize = 256;
const MAX_ID_BYTES: usize = 128;
const MAX_SCHEMA_ID_BYTES: usize = 256;
const MAX_RESOURCE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetPartition {
    Train,
    HeldOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainerDataset {
    pub partition: DatasetPartition,
    pub digest: String,
    pub schema_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardDirection {
    Maximize,
    Minimize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewardObjective {
    pub metric: String,
    pub direction: RewardDirection,
    /// Relative objective weight in millionths. Integer encoding keeps canonical JSON stable.
    pub weight_micros: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewardContract {
    pub schema_id: String,
    pub objectives: Vec<RewardObjective>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryContract {
    pub schema_id: String,
    pub max_bytes_per_trial: u64,
    pub max_events_per_trial: u32,
    /// Content-bearing trajectories require an explicit isolated store; the protocol carries only
    /// its digest and never embeds transcript content in trainer control messages.
    pub content_store_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointContract {
    pub schema_id: String,
    pub max_checkpoint_bytes: u64,
    pub checkpoint_every_trials: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainerResources {
    pub max_trials: u16,
    pub max_concurrency: u16,
    pub max_wall_secs_per_trial: u64,
    pub max_memory_bytes_per_trial: u64,
    pub max_evidence_bytes_per_trial: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributedTrials {
    pub coordinator_id: String,
    pub max_workers: u16,
    pub lease_secs: u32,
    pub heartbeat_secs: u32,
    pub max_attempts_per_trial: u8,
}

/// The complete method-neutral envelope an optimizer must pin before issuing work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainerBridgeSpec {
    pub schema_version: u16,
    /// Stable experiment identity shared by every correlated trainer exchange.
    pub experiment_id: String,
    pub train: TrainerDataset,
    pub held_out: TrainerDataset,
    pub reward: RewardContract,
    pub trajectory: TrajectoryContract,
    pub checkpoint: CheckpointContract,
    pub resources: TrainerResources,
    pub distributed: DistributedTrials,
    /// Sorted host/spec capabilities offered to an optimizer. Schema v1 requires this to be empty.
    #[serde(default)]
    pub capabilities: Vec<TrainerCapability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainerCapability {
    Batch,
    Asynchronous,
    Population,
    Bandit,
    MultiObjective,
    Trajectory,
    CheckpointResume,
    OpaqueArtifact,
}

pub const ALL_TRAINER_CAPABILITIES: [TrainerCapability; 8] = [
    TrainerCapability::Batch,
    TrainerCapability::Asynchronous,
    TrainerCapability::Population,
    TrainerCapability::Bandit,
    TrainerCapability::MultiObjective,
    TrainerCapability::Trajectory,
    TrainerCapability::CheckpointResume,
    TrainerCapability::OpaqueArtifact,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizerCapabilityOffer {
    pub optimizer_id: String,
    pub capabilities: Vec<TrainerCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainerCapabilityNegotiation {
    pub experiment_id: String,
    pub optimizer_id: String,
    pub capabilities: Vec<TrainerCapability>,
    pub negotiation_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainerOperation {
    Suggest,
    Observe,
    Checkpoint,
    Resume,
}

/// One correlated trainer exchange. Optional fields are operation-specific and validated as a
/// closed state machine rather than accepted and ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainerExchange {
    pub schema_version: u16,
    pub request_id: String,
    pub experiment_id: String,
    pub operation: TrainerOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimizer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiation_sha256: Option<String>,
    pub trial_id: Option<String>,
    pub candidate_digest: Option<String>,
    pub checkpoint_digest: Option<String>,
    pub trajectory_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub suggestion_ids: Vec<String>,
    #[serde(default)]
    pub candidate_digests: Vec<String>,
    #[serde(default)]
    pub required_capabilities: Vec<TrainerCapability>,
    #[serde(default)]
    pub rewards_micros: BTreeMap<String, i64>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrainerBridgeError {
    #[error("trainer bridge JSON exceeds its byte bound")]
    TooLarge,
    #[error("invalid trainer bridge JSON: {0}")]
    Json(String),
    #[error("unsupported trainer bridge schema version")]
    Schema,
    #[error("invalid trainer bridge field: {0}")]
    Field(&'static str),
    #[error("train and held-out datasets must be distinct and correctly partitioned")]
    DatasetIsolation,
    #[error("trainer exchange fields do not match its operation")]
    OperationShape,
    #[error("trainer exchange belongs to a different experiment")]
    Correlation,
    #[error("trainer capability is unsupported by the negotiated intersection")]
    UnsupportedCapability,
    #[error("trainer capability negotiation identity mismatch")]
    Negotiation,
}

pub fn parse_trainer_bridge_spec(bytes: &[u8]) -> Result<TrainerBridgeSpec, TrainerBridgeError> {
    let spec: TrainerBridgeSpec = parse_bounded(bytes)?;
    spec.validate()?;
    Ok(spec)
}

pub fn parse_trainer_exchange(
    bytes: &[u8],
    spec: &TrainerBridgeSpec,
) -> Result<TrainerExchange, TrainerBridgeError> {
    let exchange: TrainerExchange = parse_bounded(bytes)?;
    exchange.validate(spec)?;
    Ok(exchange)
}

pub fn parse_negotiated_trainer_exchange(
    bytes: &[u8],
    spec: &TrainerBridgeSpec,
    negotiation: &TrainerCapabilityNegotiation,
) -> Result<TrainerExchange, TrainerBridgeError> {
    let exchange: TrainerExchange = parse_bounded(bytes)?;
    exchange.validate_negotiated(spec, negotiation)?;
    Ok(exchange)
}

fn parse_bounded<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, TrainerBridgeError> {
    if bytes.len() > MAX_TRAINER_BRIDGE_MESSAGE_BYTES {
        return Err(TrainerBridgeError::TooLarge);
    }
    let value = crate::strict_json::parse_json_no_duplicates(bytes)
        .map_err(|error| TrainerBridgeError::Json(error.to_string()))?;
    serde_json::from_value(value).map_err(|error| TrainerBridgeError::Json(error.to_string()))
}

impl TrainerBridgeSpec {
    pub fn validate(&self) -> Result<(), TrainerBridgeError> {
        if !matches!(
            self.schema_version,
            LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION | TRAINER_BRIDGE_SCHEMA_VERSION
        ) {
            return Err(TrainerBridgeError::Schema);
        }
        validate_capabilities(&self.capabilities)?;
        if (self.schema_version == LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION)
            != self.capabilities.is_empty()
        {
            return Err(TrainerBridgeError::Field("capabilities"));
        }
        validate_id(&self.experiment_id, "experiment_id")?;
        validate_dataset(&self.train, DatasetPartition::Train)?;
        validate_dataset(&self.held_out, DatasetPartition::HeldOut)?;
        if self.train.digest == self.held_out.digest {
            return Err(TrainerBridgeError::DatasetIsolation);
        }
        validate_schema_id(&self.reward.schema_id)?;
        if self.reward.objectives.is_empty() || self.reward.objectives.len() > MAX_REWARD_OBJECTIVES
        {
            return Err(TrainerBridgeError::Field("reward.objectives"));
        }
        let mut metrics = BTreeSet::new();
        let mut weight = 0_u64;
        for objective in &self.reward.objectives {
            validate_id(&objective.metric, "reward.metric")?;
            if objective.weight_micros == 0 || !metrics.insert(&objective.metric) {
                return Err(TrainerBridgeError::Field("reward.objectives"));
            }
            weight = weight
                .checked_add(u64::from(objective.weight_micros))
                .ok_or(TrainerBridgeError::Field("reward.weight_micros"))?;
        }
        if weight != 1_000_000 {
            return Err(TrainerBridgeError::Field("reward.weight_micros"));
        }
        validate_schema_id(&self.trajectory.schema_id)?;
        if self.trajectory.max_bytes_per_trial == 0
            || self.trajectory.max_bytes_per_trial > MAX_RESOURCE_BYTES
            || self.trajectory.max_events_per_trial == 0
        {
            return Err(TrainerBridgeError::Field("trajectory"));
        }
        validate_schema_id(&self.checkpoint.schema_id)?;
        if self.checkpoint.max_checkpoint_bytes == 0
            || self.checkpoint.max_checkpoint_bytes > MAX_RESOURCE_BYTES
            || self.checkpoint.checkpoint_every_trials == 0
        {
            return Err(TrainerBridgeError::Field("checkpoint"));
        }
        let resources = &self.resources;
        if resources.max_trials == 0
            || resources.max_concurrency == 0
            || resources.max_concurrency > resources.max_trials
            || resources.max_wall_secs_per_trial == 0
            || resources.max_wall_secs_per_trial > 86_400
            || resources.max_memory_bytes_per_trial == 0
            || resources.max_memory_bytes_per_trial > MAX_RESOURCE_BYTES
            || resources.max_evidence_bytes_per_trial == 0
            || resources.max_evidence_bytes_per_trial > MAX_RESOURCE_BYTES
        {
            return Err(TrainerBridgeError::Field("resources"));
        }
        let distributed = &self.distributed;
        validate_id(&distributed.coordinator_id, "coordinator_id")?;
        if distributed.max_workers == 0
            || distributed.max_workers > MAX_DISTRIBUTED_WORKERS
            || distributed.max_workers > resources.max_concurrency
            || distributed.heartbeat_secs == 0
            || distributed.lease_secs <= distributed.heartbeat_secs
            || distributed.max_attempts_per_trial == 0
            || distributed.max_attempts_per_trial > 8
        {
            return Err(TrainerBridgeError::Field("distributed"));
        }
        Ok(())
    }

    /// Negotiate without granting any authority: the result is the deterministic set
    /// intersection between the host/spec and optimizer offers.
    pub fn negotiate(
        &self,
        optimizer: &OptimizerCapabilityOffer,
    ) -> Result<TrainerCapabilityNegotiation, TrainerBridgeError> {
        self.validate()?;
        validate_id(&optimizer.optimizer_id, "optimizer_id")?;
        validate_capabilities(&optimizer.capabilities)?;
        if self.schema_version != TRAINER_BRIDGE_SCHEMA_VERSION {
            return Err(TrainerBridgeError::UnsupportedCapability);
        }
        let offered = optimizer
            .capabilities
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let capabilities = self
            .capabilities
            .iter()
            .copied()
            .filter(|capability| offered.contains(capability))
            .collect::<Vec<_>>();
        let negotiation_sha256 =
            negotiation_digest(&self.experiment_id, &optimizer.optimizer_id, &capabilities)?;
        Ok(TrainerCapabilityNegotiation {
            experiment_id: self.experiment_id.clone(),
            optimizer_id: optimizer.optimizer_id.clone(),
            capabilities,
            negotiation_sha256,
        })
    }
}

impl TrainerExchange {
    pub fn validate(&self, spec: &TrainerBridgeSpec) -> Result<(), TrainerBridgeError> {
        spec.validate()?;
        if self.schema_version != spec.schema_version {
            return Err(TrainerBridgeError::Schema);
        }
        validate_id(&self.request_id, "request_id")?;
        validate_id(&self.experiment_id, "experiment_id")?;
        if self.experiment_id != spec.experiment_id {
            return Err(TrainerBridgeError::Correlation);
        }
        validate_capabilities(&self.required_capabilities)?;
        if self
            .required_capabilities
            .iter()
            .any(|capability| !spec.capabilities.contains(capability))
        {
            return Err(TrainerBridgeError::UnsupportedCapability);
        }
        if self.schema_version == LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION
            && (self.optimizer_id.is_some()
                || self.negotiation_sha256.is_some()
                || self.batch_id.is_some()
                || !self.suggestion_ids.is_empty()
                || !self.candidate_digests.is_empty()
                || !self.required_capabilities.is_empty())
        {
            return Err(TrainerBridgeError::OperationShape);
        } else if self.schema_version != LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION {
            if self
                .optimizer_id
                .as_deref()
                .is_none_or(|value| validate_id(value, "optimizer_id").is_err())
                || self
                    .negotiation_sha256
                    .as_deref()
                    .is_none_or(|value| !valid_digest(value))
            {
                return Err(TrainerBridgeError::Negotiation);
            }
            validate_batch_correlation(self)?;
        }
        let shape_ok = match self.operation {
            TrainerOperation::Suggest => {
                self.trial_id.is_none()
                    && self.candidate_digest.is_none()
                    && self.checkpoint_digest.is_none()
                    && self.trajectory_digest.is_none()
                    && self.rewards_micros.is_empty()
                    && (self.schema_version == LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION
                        || !self.suggestion_ids.is_empty())
            }
            TrainerOperation::Observe => {
                self.trial_id.as_deref().is_some_and(valid_id)
                    && self.candidate_digest.as_deref().is_some_and(valid_digest)
                    && self.checkpoint_digest.is_none()
                    && self.trajectory_digest.as_deref().is_some_and(valid_digest)
                    && !self.rewards_micros.is_empty()
                    && self.rewards_micros.len() == spec.reward.objectives.len()
                    && spec
                        .reward
                        .objectives
                        .iter()
                        .all(|objective| self.rewards_micros.contains_key(&objective.metric))
                    && (self.schema_version == LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION
                        || (self.suggestion_ids.len() == 1 && self.candidate_digests.is_empty()))
            }
            TrainerOperation::Checkpoint => {
                self.trial_id.is_none()
                    && self.candidate_digest.is_none()
                    && self.checkpoint_digest.as_deref().is_some_and(valid_digest)
                    && self.trajectory_digest.is_none()
                    && self.rewards_micros.is_empty()
                    && self.batch_id.is_none()
                    && self.suggestion_ids.is_empty()
                    && self.candidate_digests.is_empty()
            }
            TrainerOperation::Resume => {
                self.trial_id.is_none()
                    && self.candidate_digest.is_none()
                    && self.checkpoint_digest.as_deref().is_some_and(valid_digest)
                    && self.trajectory_digest.is_none()
                    && self.rewards_micros.is_empty()
                    && self.batch_id.is_none()
                    && self.suggestion_ids.is_empty()
                    && self.candidate_digests.is_empty()
            }
        };
        if !shape_ok {
            return Err(TrainerBridgeError::OperationShape);
        }
        let requires = |capability| self.required_capabilities.contains(&capability);
        if self.schema_version == TRAINER_BRIDGE_SCHEMA_VERSION
            && ((self.operation == TrainerOperation::Observe
                && spec.reward.objectives.len() > 1
                && !requires(TrainerCapability::MultiObjective))
                || (self.trajectory_digest.is_some() && !requires(TrainerCapability::Trajectory))
                || (matches!(
                    self.operation,
                    TrainerOperation::Checkpoint | TrainerOperation::Resume
                ) && !requires(TrainerCapability::CheckpointResume)))
        {
            return Err(TrainerBridgeError::UnsupportedCapability);
        }
        Ok(())
    }

    pub fn validate_negotiated(
        &self,
        spec: &TrainerBridgeSpec,
        negotiation: &TrainerCapabilityNegotiation,
    ) -> Result<(), TrainerBridgeError> {
        self.validate(spec)?;
        negotiation.validate(spec)?;
        if self.optimizer_id.as_deref() != Some(negotiation.optimizer_id.as_str())
            || self.negotiation_sha256.as_deref() != Some(negotiation.negotiation_sha256.as_str())
        {
            return Err(TrainerBridgeError::Negotiation);
        }
        if self
            .required_capabilities
            .iter()
            .any(|capability| !negotiation.capabilities.contains(capability))
        {
            return Err(TrainerBridgeError::UnsupportedCapability);
        }
        Ok(())
    }
}

impl TrainerCapabilityNegotiation {
    pub fn validate(&self, spec: &TrainerBridgeSpec) -> Result<(), TrainerBridgeError> {
        spec.validate()?;
        validate_id(&self.optimizer_id, "optimizer_id")?;
        validate_capabilities(&self.capabilities)?;
        if self.experiment_id != spec.experiment_id
            || self
                .capabilities
                .iter()
                .any(|capability| !spec.capabilities.contains(capability))
            || self.negotiation_sha256
                != negotiation_digest(&self.experiment_id, &self.optimizer_id, &self.capabilities)?
        {
            return Err(TrainerBridgeError::Negotiation);
        }
        Ok(())
    }

    pub fn supports(&self, capability: TrainerCapability) -> bool {
        self.capabilities.binary_search(&capability).is_ok()
    }
}

fn validate_batch_correlation(exchange: &TrainerExchange) -> Result<(), TrainerBridgeError> {
    if exchange.suggestion_ids.len() > MAX_BATCH_SUGGESTIONS
        || (!exchange.candidate_digests.is_empty()
            && exchange.candidate_digests.len() != exchange.suggestion_ids.len())
        || exchange.suggestion_ids.iter().any(|item| !valid_id(item))
        || exchange
            .candidate_digests
            .iter()
            .any(|item| !valid_digest(item))
    {
        return Err(TrainerBridgeError::OperationShape);
    }
    let unique_suggestions = exchange.suggestion_ids.iter().collect::<BTreeSet<_>>();
    if unique_suggestions.len() != exchange.suggestion_ids.len() {
        return Err(TrainerBridgeError::OperationShape);
    }
    if let Some(batch_id) = &exchange.batch_id {
        validate_id(batch_id, "batch_id")?;
    }
    if exchange.suggestion_ids.len() > 1
        && (exchange.batch_id.is_none()
            || !exchange
                .required_capabilities
                .contains(&TrainerCapability::Batch))
    {
        return Err(TrainerBridgeError::UnsupportedCapability);
    }
    Ok(())
}

fn validate_capabilities(capabilities: &[TrainerCapability]) -> Result<(), TrainerBridgeError> {
    if capabilities.len() > ALL_TRAINER_CAPABILITIES.len()
        || !capabilities.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(TrainerBridgeError::Field("capabilities"));
    }
    Ok(())
}

fn negotiation_digest(
    experiment_id: &str,
    optimizer_id: &str,
    capabilities: &[TrainerCapability],
) -> Result<String, TrainerBridgeError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        schema_id: &'static str,
        experiment_id: &'a str,
        optimizer_id: &'a str,
        capabilities: &'a [TrainerCapability],
    }
    let bytes = serde_json::to_vec(&Identity {
        schema_id: "iteron-trainer-capabilities/1",
        experiment_id,
        optimizer_id,
        capabilities,
    })
    .map_err(|_| TrainerBridgeError::Negotiation)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn validate_dataset(
    dataset: &TrainerDataset,
    expected: DatasetPartition,
) -> Result<(), TrainerBridgeError> {
    if dataset.partition != expected || !valid_digest(&dataset.digest) {
        return Err(TrainerBridgeError::DatasetIsolation);
    }
    validate_schema_id(&dataset.schema_id)
}

fn validate_schema_id(value: &str) -> Result<(), TrainerBridgeError> {
    if value.len() > MAX_SCHEMA_ID_BYTES || !valid_id(value) || !value.contains('/') {
        return Err(TrainerBridgeError::Field("schema_id"));
    }
    Ok(())
}

fn validate_id(value: &str, field: &'static str) -> Result<(), TrainerBridgeError> {
    if !valid_id(value) {
        return Err(TrainerBridgeError::Field(field));
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
        })
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> TrainerBridgeSpec {
        TrainerBridgeSpec {
            schema_version: LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION,
            experiment_id: "experiment-1".into(),
            train: TrainerDataset {
                partition: DatasetPartition::Train,
                digest: format!("sha256:{}", "a".repeat(64)),
                schema_id: "dataset/train@v1".into(),
            },
            held_out: TrainerDataset {
                partition: DatasetPartition::HeldOut,
                digest: format!("sha256:{}", "b".repeat(64)),
                schema_id: "dataset/held-out@v1".into(),
            },
            reward: RewardContract {
                schema_id: "reward/quality@v1".into(),
                objectives: vec![RewardObjective {
                    metric: "quality".into(),
                    direction: RewardDirection::Maximize,
                    weight_micros: 1_000_000,
                }],
            },
            trajectory: TrajectoryContract {
                schema_id: "trajectory/events@v1".into(),
                max_bytes_per_trial: 1024,
                max_events_per_trial: 16,
                content_store_required: true,
            },
            checkpoint: CheckpointContract {
                schema_id: "checkpoint/tuner@v1".into(),
                max_checkpoint_bytes: 1024,
                checkpoint_every_trials: 1,
            },
            resources: TrainerResources {
                max_trials: 2,
                max_concurrency: 1,
                max_wall_secs_per_trial: 60,
                max_memory_bytes_per_trial: 1024,
                max_evidence_bytes_per_trial: 1024,
            },
            distributed: DistributedTrials {
                coordinator_id: "local/coordinator".into(),
                max_workers: 1,
                lease_secs: 10,
                heartbeat_secs: 2,
                max_attempts_per_trial: 1,
            },
            capabilities: Vec::new(),
        }
    }

    #[test]
    fn dataset_isolation_and_resource_bounds_are_closed() {
        let valid = spec();
        assert_eq!(valid.validate(), Ok(()));
        let mut aliased = valid.clone();
        aliased.held_out.digest = aliased.train.digest.clone();
        assert_eq!(
            aliased.validate(),
            Err(TrainerBridgeError::DatasetIsolation)
        );
        let mut unbounded = valid;
        unbounded.distributed.max_workers = MAX_DISTRIBUTED_WORKERS + 1;
        assert_eq!(
            unbounded.validate(),
            Err(TrainerBridgeError::Field("distributed"))
        );
    }

    #[test]
    fn operation_shapes_are_not_silently_ignored() {
        let contract = spec();
        let observe = TrainerExchange {
            schema_version: LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION,
            request_id: "request-1".into(),
            experiment_id: "experiment-1".into(),
            operation: TrainerOperation::Observe,
            optimizer_id: None,
            negotiation_sha256: None,
            trial_id: Some("trial-1".into()),
            candidate_digest: Some(format!("sha256:{}", "c".repeat(64))),
            checkpoint_digest: None,
            trajectory_digest: Some(format!("sha256:{}", "d".repeat(64))),
            batch_id: None,
            suggestion_ids: Vec::new(),
            candidate_digests: Vec::new(),
            required_capabilities: Vec::new(),
            rewards_micros: BTreeMap::from([("quality".into(), 900_000)]),
        };
        assert_eq!(observe.validate(&contract), Ok(()));
        let mut wrong = observe;
        wrong.checkpoint_digest = Some(format!("sha256:{}", "e".repeat(64)));
        assert_eq!(
            wrong.validate(&contract),
            Err(TrainerBridgeError::OperationShape)
        );

        let mut rebound = TrainerExchange {
            schema_version: LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION,
            request_id: "request-2".into(),
            experiment_id: "other-experiment".into(),
            operation: TrainerOperation::Suggest,
            optimizer_id: None,
            negotiation_sha256: None,
            trial_id: None,
            candidate_digest: None,
            checkpoint_digest: None,
            trajectory_digest: None,
            batch_id: None,
            suggestion_ids: Vec::new(),
            candidate_digests: Vec::new(),
            required_capabilities: Vec::new(),
            rewards_micros: BTreeMap::new(),
        };
        assert_eq!(
            rebound.validate(&contract),
            Err(TrainerBridgeError::Correlation)
        );
        rebound.experiment_id = contract.experiment_id.clone();
        assert_eq!(rebound.validate(&contract), Ok(()));
    }

    #[test]
    fn external_json_is_bounded_closed_and_duplicate_free() {
        let contract = spec();
        let bytes = serde_json::to_vec(&contract).unwrap();
        assert_eq!(parse_trainer_bridge_spec(&bytes).unwrap(), contract);

        let duplicate = br#"{"schema_version":1,"schema_version":1}"#;
        assert!(matches!(
            parse_trainer_bridge_spec(duplicate),
            Err(TrainerBridgeError::Json(_))
        ));
        let oversized = vec![b' '; MAX_TRAINER_BRIDGE_MESSAGE_BYTES + 1];
        assert_eq!(
            parse_trainer_bridge_spec(&oversized),
            Err(TrainerBridgeError::TooLarge)
        );
    }

    #[test]
    fn optimizer_families_negotiate_only_the_supported_intersection() {
        let mut contract = spec();
        contract.schema_version = TRAINER_BRIDGE_SCHEMA_VERSION;
        contract.capabilities = ALL_TRAINER_CAPABILITIES.to_vec();
        let profiles = [
            (
                "tpe-bayesian",
                vec![
                    TrainerCapability::Asynchronous,
                    TrainerCapability::MultiObjective,
                    TrainerCapability::CheckpointResume,
                ],
            ),
            (
                "population-evolution",
                vec![
                    TrainerCapability::Batch,
                    TrainerCapability::Population,
                    TrainerCapability::Trajectory,
                ],
            ),
            (
                "bandit-halving",
                vec![TrainerCapability::Asynchronous, TrainerCapability::Bandit],
            ),
            (
                "llm-optimizer",
                vec![
                    TrainerCapability::Trajectory,
                    TrainerCapability::OpaqueArtifact,
                ],
            ),
            (
                "episode-rl",
                vec![
                    TrainerCapability::Asynchronous,
                    TrainerCapability::Trajectory,
                    TrainerCapability::CheckpointResume,
                ],
            ),
        ];
        for (optimizer_id, capabilities) in profiles {
            let negotiated = contract
                .negotiate(&OptimizerCapabilityOffer {
                    optimizer_id: optimizer_id.into(),
                    capabilities: capabilities.clone(),
                })
                .unwrap();
            assert_eq!(negotiated.capabilities, capabilities);
            assert!(negotiated.validate(&contract).is_ok());
        }

        let negotiated = contract
            .negotiate(&OptimizerCapabilityOffer {
                optimizer_id: "tpe-bayesian".into(),
                capabilities: vec![TrainerCapability::Asynchronous],
            })
            .unwrap();
        let batch = TrainerExchange {
            schema_version: TRAINER_BRIDGE_SCHEMA_VERSION,
            request_id: "batch-request".into(),
            experiment_id: contract.experiment_id.clone(),
            operation: TrainerOperation::Suggest,
            optimizer_id: Some(negotiated.optimizer_id.clone()),
            negotiation_sha256: Some(negotiated.negotiation_sha256.clone()),
            trial_id: None,
            candidate_digest: None,
            checkpoint_digest: None,
            trajectory_digest: None,
            batch_id: Some("batch-1".into()),
            suggestion_ids: vec!["suggestion-1".into(), "suggestion-2".into()],
            candidate_digests: Vec::new(),
            required_capabilities: vec![TrainerCapability::Batch],
            rewards_micros: BTreeMap::new(),
        };
        assert_eq!(
            batch.validate_negotiated(&contract, &negotiated),
            Err(TrainerBridgeError::UnsupportedCapability)
        );
    }
}
