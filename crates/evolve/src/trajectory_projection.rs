//! Deterministic projection from bounded recorded-run fixtures into governed trajectories.
//!
//! The real recorder remains a separate crate and no dependency edge is added here. Its stable,
//! content-minimal handoff is represented by [`RecordedRunFixture`]: a rollout digest, checkpoint
//! digest, terminal outcome, reward/governance fields, and raw strategy decisions. Projection
//! recomputes every action digest through [`crate::EvidenceRecorder`] before returning a
//! [`crate::TrajectoryEnvelope`].

use crate::{
    ContractError, DataGovernance, EvidenceRecorder, MAX_DECISIONS_PER_TRAJECTORY,
    MAX_SHORT_STRING_BYTES, PolicyBundle, PolicyRef, RewardVector, StrategyDecision,
    TrainingAdmissionPolicy, TrajectoryEnvelope, TrajectoryProjection, validate_collection,
    validate_digest, validate_nonempty_string,
};
use core_protocol::{RunId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const RECORDED_RUN_FIXTURE_SCHEMA_VERSION: u16 = 1;
pub const MAX_RECORDED_RUN_FIXTURES: usize = 1_024;
pub const MAX_RECORDED_RUN_FIXTURE_JSON_BYTES: usize = 4 * 1024 * 1024;

/// A recorder-side strategy decision before evolution derives its canonical action digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedDecision {
    pub decision_id: String,
    pub ordinal: u64,
    pub policy: PolicyRef,
    pub observation_digest: String,
    pub candidate_set_digest: String,
    pub action: serde_json::Value,
    pub propensity: Option<f64>,
}

/// Content-minimal stable handoff from one hash-chained recorded run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedRunFixture {
    pub schema_version: u16,
    pub rollout_digest: String,
    pub checkpoint_digest: String,
    pub run_id: RunId,
    pub tenant_id: TenantId,
    pub task_id: String,
    pub domain: String,
    pub bundle: PolicyBundle,
    pub decisions: Vec<RecordedDecision>,
    pub terminal_outcome: String,
    pub reward: RewardVector,
    pub governance: DataGovernance,
    /// A consent registry can revoke a previously allowed run without rewriting its record.
    #[serde(default)]
    pub training_revoked: bool,
}

impl RecordedRunFixture {
    pub fn from_json(bytes: &[u8]) -> Result<Self, RecordedRunProjectorError> {
        if bytes.len() > MAX_RECORDED_RUN_FIXTURE_JSON_BYTES {
            return Err(RecordedRunProjectorError::FixtureTooLarge {
                max: MAX_RECORDED_RUN_FIXTURE_JSON_BYTES,
                actual: bytes.len(),
            });
        }
        let fixture =
            serde_json::from_slice(bytes).map_err(RecordedRunProjectorError::InvalidFixtureJson)?;
        Self::validate_shape(&fixture)?;
        Ok(fixture)
    }

    fn validate_shape(&self) -> Result<(), RecordedRunProjectorError> {
        if self.schema_version != RECORDED_RUN_FIXTURE_SCHEMA_VERSION {
            return Err(RecordedRunProjectorError::UnsupportedFixtureSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.rollout_digest)?;
        validate_digest(&self.checkpoint_digest)?;
        validate_nonempty_string(
            "recorded_run.run_id",
            &self.run_id.0,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string(
            "recorded_run.tenant_id",
            &self.tenant_id.0,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string(
            "recorded_run.task_id",
            &self.task_id,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string("recorded_run.domain", &self.domain, MAX_SHORT_STRING_BYTES)?;
        validate_nonempty_string(
            "recorded_run.terminal_outcome",
            &self.terminal_outcome,
            MAX_SHORT_STRING_BYTES,
        )?;
        self.bundle.validate()?;
        self.reward.validate()?;
        self.governance.validate()?;
        validate_collection(
            "recorded_run.decisions",
            self.decisions.len(),
            MAX_DECISIONS_PER_TRAJECTORY,
        )?;
        let mut decision_ids = BTreeSet::new();
        let mut ordinals = BTreeSet::new();
        for (index, decision) in self.decisions.iter().enumerate() {
            validate_nonempty_string(
                "recorded_decision.decision_id",
                &decision.decision_id,
                MAX_SHORT_STRING_BYTES,
            )?;
            decision.policy.validate()?;
            validate_digest(&decision.observation_digest)?;
            validate_digest(&decision.candidate_set_digest)?;
            if self.bundle.policy_for(&decision.policy.slot) != Some(&decision.policy) {
                return Err(RecordedRunProjectorError::DecisionPolicyMismatch);
            }
            if let Some(propensity) = decision.propensity
                && (!propensity.is_finite() || propensity <= 0.0 || propensity > 1.0)
            {
                return Err(RecordedRunProjectorError::InvalidPropensity);
            }
            if !decision_ids.insert(decision.decision_id.clone())
                || !ordinals.insert(decision.ordinal)
            {
                return Err(RecordedRunProjectorError::DuplicateDecisionIdentity);
            }
            if decision.ordinal != index as u64 {
                return Err(RecordedRunProjectorError::NonCanonicalDecisionOrder);
            }
        }
        if self.canonical_rollout_digest()? != self.rollout_digest {
            return Err(RecordedRunProjectorError::RolloutDigestMismatch);
        }
        Ok(())
    }

    /// Digest of the immutable recorder content represented by this fixture.
    ///
    /// `training_revoked` is intentionally excluded: it models later consent-registry state, which
    /// may make an otherwise immutable run ineligible without rewriting the recorded run itself.
    pub fn canonical_rollout_digest(&self) -> Result<String, RecordedRunProjectorError> {
        #[derive(Serialize)]
        struct RecordedContent<'a> {
            schema_version: u16,
            checkpoint_digest: &'a str,
            run_id: &'a RunId,
            tenant_id: &'a TenantId,
            task_id: &'a str,
            domain: &'a str,
            bundle: &'a PolicyBundle,
            decisions: &'a [RecordedDecision],
            terminal_outcome: &'a str,
            reward: &'a RewardVector,
            governance: &'a DataGovernance,
        }
        let bytes = serde_json::to_vec(&RecordedContent {
            schema_version: self.schema_version,
            checkpoint_digest: &self.checkpoint_digest,
            run_id: &self.run_id,
            tenant_id: &self.tenant_id,
            task_id: &self.task_id,
            domain: &self.domain,
            bundle: &self.bundle,
            decisions: &self.decisions,
            terminal_outcome: &self.terminal_outcome,
            reward: &self.reward,
            governance: &self.governance,
        })
        .map_err(RecordedRunProjectorError::CanonicalEncoding)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn project(&self) -> Result<TrajectoryEnvelope, ContractError> {
        let mut envelope = TrajectoryEnvelope {
            schema_version: crate::EVOLUTION_SCHEMA_VERSION,
            run_id: self.run_id.clone(),
            tenant_id: self.tenant_id.clone(),
            task_id: self.task_id.clone(),
            domain: self.domain.clone(),
            environment_digest: self.checkpoint_digest.clone(),
            bundle: self.bundle.clone(),
            decisions: Vec::with_capacity(self.decisions.len()),
            terminal_outcome: self.terminal_outcome.clone(),
            reward: self.reward.clone(),
            governance: self.governance.clone(),
        };
        for decision in &self.decisions {
            EvidenceRecorder::new()
                .record_decision(
                    &mut envelope,
                    StrategyDecision {
                        decision_id: decision.decision_id.clone(),
                        ordinal: decision.ordinal,
                        policy: decision.policy.clone(),
                        observation_digest: decision.observation_digest.clone(),
                        candidate_set_digest: decision.candidate_set_digest.clone(),
                        action: decision.action.clone(),
                        // Deliberately bogus: `record_decision` must overwrite it.
                        action_digest: "0".repeat(64),
                        propensity: decision.propensity,
                    },
                )
                .map_err(|_| {
                    ContractError::ProjectionFailed(
                        "a recorded decision could not be canonically content-bound",
                    )
                })?;
        }
        envelope.validate()?;
        Ok(envelope)
    }
}

/// In-memory bounded fixture index implementing the frozen record -> evolve seam.
#[derive(Debug, Clone)]
pub struct RecordedRunProjector {
    fixtures: BTreeMap<String, RecordedRunFixture>,
    training_policy: TrainingAdmissionPolicy,
}

impl RecordedRunProjector {
    pub fn new(
        fixtures: Vec<RecordedRunFixture>,
        training_policy: TrainingAdmissionPolicy,
    ) -> Result<Self, RecordedRunProjectorError> {
        training_policy.validate()?;
        if fixtures.len() > MAX_RECORDED_RUN_FIXTURES {
            return Err(RecordedRunProjectorError::FixtureLimit {
                max: MAX_RECORDED_RUN_FIXTURES,
                actual: fixtures.len(),
            });
        }
        let mut indexed = BTreeMap::new();
        for fixture in fixtures {
            fixture.validate_shape()?;
            if indexed
                .insert(fixture.rollout_digest.clone(), fixture)
                .is_some()
            {
                return Err(RecordedRunProjectorError::DuplicateRolloutDigest);
            }
        }
        Ok(Self {
            fixtures: indexed,
            training_policy,
        })
    }

    pub fn len(&self) -> usize {
        self.fixtures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fixtures.is_empty()
    }
}

impl TrajectoryProjection for RecordedRunProjector {
    fn project(&self, rollout_digest: &str) -> Result<Option<TrajectoryEnvelope>, ContractError> {
        validate_digest(rollout_digest)?;
        let Some(fixture) = self.fixtures.get(rollout_digest) else {
            return Ok(None);
        };
        if fixture.training_revoked {
            return Ok(None);
        }
        let envelope = fixture.project()?;
        if self.training_policy.validate_trajectory(&envelope).is_err() {
            return Ok(None);
        }
        Ok(Some(envelope))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordedRunProjectorError {
    #[error("recorded-run fixture JSON is invalid: {0}")]
    InvalidFixtureJson(#[source] serde_json::Error),
    #[error("recorded-run fixture JSON is {actual} bytes; limit is {max}")]
    FixtureTooLarge { max: usize, actual: usize },
    #[error("recorded-run canonical content could not be encoded: {0}")]
    CanonicalEncoding(#[source] serde_json::Error),
    #[error("recorded-run fixture schema {0} is unsupported")]
    UnsupportedFixtureSchema(u16),
    #[error("recorded-run fixture contract is invalid: {0}")]
    InvalidContract(#[from] ContractError),
    #[error("recorded-run fixture count is {actual}; limit is {max}")]
    FixtureLimit { max: usize, actual: usize },
    #[error("recorded-run fixtures contain a duplicate rollout digest")]
    DuplicateRolloutDigest,
    #[error("recorded-run fixture contains a decision not present in its active bundle")]
    DecisionPolicyMismatch,
    #[error("recorded-run fixture contains a duplicate decision id or ordinal")]
    DuplicateDecisionIdentity,
    #[error("recorded-run fixture decisions are not in contiguous canonical ordinal order")]
    NonCanonicalDecisionOrder,
    #[error("recorded-run fixture contains an invalid propensity")]
    InvalidPropensity,
    #[error("recorded-run fixture rollout digest does not bind its immutable canonical content")]
    RolloutDigestMismatch,
}

#[cfg(test)]
#[path = "trajectory_projection_tests.rs"]
mod tests;
