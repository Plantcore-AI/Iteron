//! Method-neutral contracts shared by Iteron's native tuner and external optimizers.
//!
//! These records describe data, observations and resumable work. They do not select a winner,
//! activate a candidate, or grant a capability. All authority remains with the host that validates
//! and runs the candidate.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const TRAINER_BRIDGE_SCHEMA_VERSION: u16 = 1;
pub const MAX_TRAINER_BRIDGE_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_REWARD_OBJECTIVES: usize = 32;
pub const MAX_DISTRIBUTED_WORKERS: u16 = 256;
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
    pub trial_id: Option<String>,
    pub candidate_digest: Option<String>,
    pub checkpoint_digest: Option<String>,
    pub trajectory_digest: Option<String>,
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
        if self.schema_version != TRAINER_BRIDGE_SCHEMA_VERSION {
            return Err(TrainerBridgeError::Schema);
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
}

impl TrainerExchange {
    pub fn validate(&self, spec: &TrainerBridgeSpec) -> Result<(), TrainerBridgeError> {
        spec.validate()?;
        if self.schema_version != TRAINER_BRIDGE_SCHEMA_VERSION {
            return Err(TrainerBridgeError::Schema);
        }
        validate_id(&self.request_id, "request_id")?;
        validate_id(&self.experiment_id, "experiment_id")?;
        if self.experiment_id != spec.experiment_id {
            return Err(TrainerBridgeError::Correlation);
        }
        let shape_ok = match self.operation {
            TrainerOperation::Suggest => {
                self.trial_id.is_none()
                    && self.candidate_digest.is_none()
                    && self.checkpoint_digest.is_none()
                    && self.trajectory_digest.is_none()
                    && self.rewards_micros.is_empty()
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
            }
            TrainerOperation::Checkpoint => {
                self.trial_id.is_none()
                    && self.candidate_digest.is_none()
                    && self.checkpoint_digest.as_deref().is_some_and(valid_digest)
                    && self.trajectory_digest.is_none()
                    && self.rewards_micros.is_empty()
            }
            TrainerOperation::Resume => {
                self.trial_id.is_none()
                    && self.candidate_digest.is_none()
                    && self.checkpoint_digest.as_deref().is_some_and(valid_digest)
                    && self.trajectory_digest.is_none()
                    && self.rewards_micros.is_empty()
            }
        };
        if !shape_ok {
            return Err(TrainerBridgeError::OperationShape);
        }
        Ok(())
    }
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
            schema_version: TRAINER_BRIDGE_SCHEMA_VERSION,
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
            schema_version: TRAINER_BRIDGE_SCHEMA_VERSION,
            request_id: "request-1".into(),
            experiment_id: "experiment-1".into(),
            operation: TrainerOperation::Observe,
            trial_id: Some("trial-1".into()),
            candidate_digest: Some(format!("sha256:{}", "c".repeat(64))),
            checkpoint_digest: None,
            trajectory_digest: Some(format!("sha256:{}", "d".repeat(64))),
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
            schema_version: TRAINER_BRIDGE_SCHEMA_VERSION,
            request_id: "request-2".into(),
            experiment_id: "other-experiment".into(),
            operation: TrainerOperation::Suggest,
            trial_id: None,
            candidate_digest: None,
            checkpoint_digest: None,
            trajectory_digest: None,
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
}
