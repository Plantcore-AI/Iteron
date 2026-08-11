//! Bounded projection of durable policy decision/outcome evidence into an offline trajectory.

use crate::{
    ContractError, DataGovernance, EvidenceRecorder, MAX_DECISIONS_PER_TRAJECTORY,
    MAX_DOMAIN_REWARDS, MAX_SHORT_STRING_BYTES, PolicyBundle, PolicyRef, RewardVector,
    StrategyDecision, StrategySlot, TrainingAdmissionPolicy, TrajectoryEnvelope,
    validate_collection, validate_digest, validate_nonempty_string,
};
use iteron_protocol::{
    PolicyDecisionEvidence, PolicyOpportunityJoinDigest, PolicyOutcomeEvidence, PolicyOutcomeScope,
    PolicyTerminalOutcome, PolicyVerifierOutcome, RunId, TenantId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const POLICY_EVIDENCE_RUN_SCHEMA_VERSION: u16 = 1;
pub const MAX_POLICY_EVIDENCE_RUNS: usize = 1_024;
pub const MAX_POLICY_EVIDENCE_RUN_JSON_BYTES: usize = 4 * 1024 * 1024;

/// Reward dimensions not present in the content-free runtime outcome contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProjectionRewardContext {
    pub safety_violations: u32,
    pub policy_violations: u32,
    pub human_acceptance: Option<f64>,
    pub domain: BTreeMap<String, f64>,
}

/// Stable record-to-evolve handoff for one terminal policy-run segment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvidenceRunFixture {
    pub schema_version: u16,
    pub rollout_digest: String,
    pub checkpoint_digest: String,
    pub run_id: RunId,
    pub tenant_id: TenantId,
    pub task_id: String,
    pub domain: String,
    pub bundle: PolicyBundle,
    pub decisions: Vec<PolicyDecisionEvidence>,
    pub outcomes: Vec<PolicyOutcomeEvidence>,
    pub reward_context: PolicyProjectionRewardContext,
    pub governance: DataGovernance,
    #[serde(default)]
    pub training_revoked: bool,
}

#[derive(Debug, Clone)]
pub struct PolicyEvidenceRunProjector {
    fixtures: BTreeMap<String, PolicyEvidenceRunFixture>,
    training_policy: TrainingAdmissionPolicy,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyEvidenceRunProjectorError {
    #[error("policy evidence fixture JSON is invalid: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("policy evidence fixture JSON is {actual} bytes; limit is {max}")]
    FixtureTooLarge { max: usize, actual: usize },
    #[error("policy evidence canonical content could not be encoded: {0}")]
    CanonicalEncoding(#[source] serde_json::Error),
    #[error("policy evidence fixture schema {0} is unsupported")]
    UnsupportedSchema(u16),
    #[error("policy evidence fixture contract is invalid: {0}")]
    InvalidContract(#[from] ContractError),
    #[error("policy evidence fixture count is {actual}; limit is {max}")]
    FixtureLimit { max: usize, actual: usize },
    #[error("policy evidence fixtures contain a duplicate rollout digest")]
    DuplicateRolloutDigest,
    #[error("policy evidence fixture rollout digest does not bind its canonical content")]
    RolloutDigestMismatch,
    #[error("policy decision or outcome is structurally invalid")]
    InvalidEvidence,
    #[error("policy evidence contains a cross-run identity")]
    CrossRunIdentity,
    #[error("policy decision identities or ordinals are duplicate or non-contiguous")]
    InvalidDecisionOrder,
    #[error("policy outcome identities or ordinals are duplicate, missing, or non-contiguous")]
    InvalidOutcomeOrder,
    #[error("policy identity differs from the immutable trajectory bundle")]
    PolicyIdentityMismatch,
    #[error("policy outcome does not commit to the exact ordered opportunities in its scope")]
    OutcomeJoinMismatch,
    #[error("run outcome does not aggregate its terminal turn outcomes")]
    RunAggregateMismatch,
    #[error("policy evidence could not be represented as bounded canonical action JSON")]
    ActionEncoding,
}

struct ValidatedJoin<'a> {
    turn_outcomes: BTreeMap<u32, &'a PolicyOutcomeEvidence>,
    run_outcome: &'a PolicyOutcomeEvidence,
}

impl PolicyEvidenceRunFixture {
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyEvidenceRunProjectorError> {
        if bytes.len() > MAX_POLICY_EVIDENCE_RUN_JSON_BYTES {
            return Err(PolicyEvidenceRunProjectorError::FixtureTooLarge {
                max: MAX_POLICY_EVIDENCE_RUN_JSON_BYTES,
                actual: bytes.len(),
            });
        }
        let fixture: Self =
            serde_json::from_slice(bytes).map_err(PolicyEvidenceRunProjectorError::InvalidJson)?;
        fixture.validate_shape()?;
        Ok(fixture)
    }

    pub fn canonical_rollout_digest(&self) -> Result<String, PolicyEvidenceRunProjectorError> {
        #[derive(Serialize)]
        struct CanonicalContent<'a> {
            schema_version: u16,
            checkpoint_digest: &'a str,
            run_id: &'a RunId,
            tenant_id: &'a TenantId,
            task_id: &'a str,
            domain: &'a str,
            bundle: &'a PolicyBundle,
            decisions: &'a [PolicyDecisionEvidence],
            outcomes: &'a [PolicyOutcomeEvidence],
            reward_context: &'a PolicyProjectionRewardContext,
            governance: &'a DataGovernance,
        }
        let bytes = serde_json::to_vec(&CanonicalContent {
            schema_version: self.schema_version,
            checkpoint_digest: &self.checkpoint_digest,
            run_id: &self.run_id,
            tenant_id: &self.tenant_id,
            task_id: &self.task_id,
            domain: &self.domain,
            bundle: &self.bundle,
            decisions: &self.decisions,
            outcomes: &self.outcomes,
            reward_context: &self.reward_context,
            governance: &self.governance,
        })
        .map_err(PolicyEvidenceRunProjectorError::CanonicalEncoding)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn validate_shape(&self) -> Result<(), PolicyEvidenceRunProjectorError> {
        if self.schema_version != POLICY_EVIDENCE_RUN_SCHEMA_VERSION {
            return Err(PolicyEvidenceRunProjectorError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.rollout_digest)?;
        validate_digest(&self.checkpoint_digest)?;
        validate_nonempty_string("policy_run.run_id", &self.run_id.0, MAX_SHORT_STRING_BYTES)?;
        validate_nonempty_string(
            "policy_run.tenant_id",
            &self.tenant_id.0,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string("policy_run.task_id", &self.task_id, MAX_SHORT_STRING_BYTES)?;
        validate_nonempty_string("policy_run.domain", &self.domain, MAX_SHORT_STRING_BYTES)?;
        self.bundle.validate()?;
        self.governance.validate()?;
        validate_collection(
            "policy_run.decisions",
            self.decisions.len(),
            MAX_DECISIONS_PER_TRAJECTORY,
        )?;
        validate_collection(
            "policy_run.outcomes",
            self.outcomes.len(),
            MAX_DECISIONS_PER_TRAJECTORY + 1,
        )?;
        self.reward_context.validate()?;
        self.validate_join()?;
        if self.canonical_rollout_digest()? != self.rollout_digest {
            return Err(PolicyEvidenceRunProjectorError::RolloutDigestMismatch);
        }
        Ok(())
    }

    fn validate_join(&self) -> Result<ValidatedJoin<'_>, PolicyEvidenceRunProjectorError> {
        let mut opportunities = BTreeSet::new();
        let mut tunables_digest = None;
        for (index, decision) in self.decisions.iter().enumerate() {
            decision
                .validate()
                .map_err(|_| PolicyEvidenceRunProjectorError::InvalidEvidence)?;
            if decision.run_id != self.run_id {
                return Err(PolicyEvidenceRunProjectorError::CrossRunIdentity);
            }
            if decision.decision_ordinal != index as u64
                || !opportunities.insert(decision.opportunity_id.clone())
            {
                return Err(PolicyEvidenceRunProjectorError::InvalidDecisionOrder);
            }
            if tunables_digest
                .replace(decision.tunables_digest_sha256.as_str())
                .is_some_and(|digest| digest != decision.tunables_digest_sha256)
            {
                return Err(PolicyEvidenceRunProjectorError::PolicyIdentityMismatch);
            }
            self.policy_ref(decision)?;
        }

        let mut turns = BTreeMap::new();
        let mut run = None;
        for (index, outcome) in self.outcomes.iter().enumerate() {
            outcome
                .validate()
                .map_err(|_| PolicyEvidenceRunProjectorError::InvalidEvidence)?;
            if outcome.run_id != self.run_id {
                return Err(PolicyEvidenceRunProjectorError::CrossRunIdentity);
            }
            if outcome.outcome_ordinal != index as u64 {
                return Err(PolicyEvidenceRunProjectorError::InvalidOutcomeOrder);
            }
            match outcome.scope {
                PolicyOutcomeScope::Turn => {
                    let turn = outcome.turn_id.expect("validated turn outcome has an id");
                    if turns.insert(turn.0, outcome).is_some() || run.is_some() {
                        return Err(PolicyEvidenceRunProjectorError::InvalidOutcomeOrder);
                    }
                    self.validate_scope_join(Some(turn.0), outcome)?;
                }
                PolicyOutcomeScope::Run => {
                    if run.replace(outcome).is_some() || index + 1 != self.outcomes.len() {
                        return Err(PolicyEvidenceRunProjectorError::InvalidOutcomeOrder);
                    }
                    self.validate_scope_join(None, outcome)?;
                }
            }
        }
        for turn in self
            .decisions
            .iter()
            .filter_map(|decision| decision.turn_id)
        {
            if !turns.contains_key(&turn.0) {
                return Err(PolicyEvidenceRunProjectorError::InvalidOutcomeOrder);
            }
        }
        let run = run.ok_or(PolicyEvidenceRunProjectorError::InvalidOutcomeOrder)?;
        validate_run_aggregate(turns.values().copied(), run)?;
        Ok(ValidatedJoin {
            turn_outcomes: turns,
            run_outcome: run,
        })
    }

    fn validate_scope_join(
        &self,
        turn: Option<u32>,
        outcome: &PolicyOutcomeEvidence,
    ) -> Result<(), PolicyEvidenceRunProjectorError> {
        let mut join = PolicyOpportunityJoinDigest::default();
        for decision in self
            .decisions
            .iter()
            .filter(|decision| turn.is_none() || decision.turn_id.map(|id| id.0) == turn)
        {
            join.append(&decision.opportunity_id)
                .map_err(|_| PolicyEvidenceRunProjectorError::InvalidEvidence)?;
        }
        if !join.matches(outcome) {
            return Err(PolicyEvidenceRunProjectorError::OutcomeJoinMismatch);
        }
        Ok(())
    }

    fn policy_ref(
        &self,
        decision: &PolicyDecisionEvidence,
    ) -> Result<PolicyRef, PolicyEvidenceRunProjectorError> {
        if decision.policy.bundle_id != self.bundle.bundle_id
            || decision.policy.bundle_digest_sha256 != self.bundle.digest
        {
            return Err(PolicyEvidenceRunProjectorError::PolicyIdentityMismatch);
        }
        let slot = StrategySlot::new(decision.slot.as_persisted_str())?;
        let policy = PolicyRef {
            slot,
            policy_id: decision.policy.policy_id.clone(),
            version: decision.policy.policy_version.clone(),
            digest: decision.policy.policy_digest_sha256.clone(),
        };
        if self.bundle.policy_for(&policy.slot) != Some(&policy) {
            return Err(PolicyEvidenceRunProjectorError::PolicyIdentityMismatch);
        }
        Ok(policy)
    }

    pub(crate) fn project_evidence(&self) -> Result<TrajectoryEnvelope, ContractError> {
        let join = self
            .validate_join()
            .map_err(|_| ContractError::ProjectionFailed("policy evidence join is invalid"))?;
        let run = join.run_outcome;
        let quality = run
            .quality_micros
            .map_or(0.0, |value| value as f64 / 1_000_000.0);
        let mut envelope = TrajectoryEnvelope {
            schema_version: crate::EVOLUTION_SCHEMA_VERSION,
            run_id: self.run_id.clone(),
            tenant_id: self.tenant_id.clone(),
            task_id: self.task_id.clone(),
            domain: self.domain.clone(),
            environment_digest: self.checkpoint_digest.clone(),
            bundle: self.bundle.clone(),
            decisions: Vec::with_capacity(self.decisions.len()),
            terminal_outcome: terminal_name(run.terminal).into(),
            reward: RewardVector {
                task_score: quality,
                correctness: quality,
                safety_violations: self.reward_context.safety_violations,
                policy_violations: self.reward_context.policy_violations,
                cost_usd: run
                    .cost_microusd
                    .map_or(0.0, |value| value as f64 / 1_000_000.0),
                wall_time_ms: run.latency_us.saturating_add(999) / 1_000,
                human_acceptance: self.reward_context.human_acceptance,
                domain: self.reward_context.domain.clone(),
            },
            governance: self.governance.clone(),
        };
        for decision in &self.decisions {
            let action = serde_json::json!({
                "policy_decision_evidence": decision,
                "turn_outcome_evidence": decision.turn_id.and_then(|id| join.turn_outcomes.get(&id.0).copied()),
                "run_outcome_evidence": run,
            });
            EvidenceRecorder::new()
                .record_decision(
                    &mut envelope,
                    StrategyDecision {
                        decision_id: decision.opportunity_id.0.clone(),
                        ordinal: decision.decision_ordinal,
                        policy: self.policy_ref(decision).map_err(|_| {
                            ContractError::ProjectionFailed("policy identity mismatch")
                        })?,
                        observation_digest: decision.feature_digest_sha256.clone(),
                        candidate_set_digest: candidate_set_digest(decision),
                        action,
                        action_digest: "0".repeat(64),
                        propensity: decision
                            .propensity_ppm
                            .map(|ppm| f64::from(ppm) / 1_000_000.0),
                    },
                )
                .map_err(|_| {
                    ContractError::ProjectionFailed("policy evidence action is invalid")
                })?;
        }
        envelope.validate()?;
        Ok(envelope)
    }
}

impl PolicyProjectionRewardContext {
    fn validate(&self) -> Result<(), ContractError> {
        if self
            .human_acceptance
            .is_some_and(|value| !value.is_finite())
            || self.domain.values().any(|value| !value.is_finite())
        {
            return Err(ContractError::NonFiniteReward);
        }
        validate_collection(
            "policy_run.reward.domain",
            self.domain.len(),
            MAX_DOMAIN_REWARDS,
        )?;
        for key in self.domain.keys() {
            validate_nonempty_string("policy_run.reward.domain key", key, MAX_SHORT_STRING_BYTES)?;
        }
        Ok(())
    }
}

impl PolicyEvidenceRunProjector {
    pub fn new(
        fixtures: Vec<PolicyEvidenceRunFixture>,
        training_policy: TrainingAdmissionPolicy,
    ) -> Result<Self, PolicyEvidenceRunProjectorError> {
        training_policy.validate()?;
        if fixtures.len() > MAX_POLICY_EVIDENCE_RUNS {
            return Err(PolicyEvidenceRunProjectorError::FixtureLimit {
                max: MAX_POLICY_EVIDENCE_RUNS,
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
                return Err(PolicyEvidenceRunProjectorError::DuplicateRolloutDigest);
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

    pub(crate) fn project_by_digest(
        &self,
        rollout_digest: &str,
    ) -> Result<Option<TrajectoryEnvelope>, ContractError> {
        validate_digest(rollout_digest)?;
        let Some(fixture) = self.fixtures.get(rollout_digest) else {
            return Ok(None);
        };
        if fixture.training_revoked {
            return Ok(None);
        }
        let envelope = fixture.project_evidence()?;
        if self.training_policy.validate_trajectory(&envelope).is_err() {
            return Ok(None);
        }
        Ok(Some(envelope))
    }
}

fn candidate_set_digest(decision: &PolicyDecisionEvidence) -> String {
    let mut actions: Vec<&str> = decision
        .eligible_actions
        .iter()
        .map(|action| action.0.as_str())
        .collect();
    actions.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(b"core-policy-candidate-set-v1\0");
    hasher.update((actions.len() as u64).to_le_bytes());
    for action in actions {
        hasher.update((action.len() as u64).to_le_bytes());
        hasher.update(action.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn validate_run_aggregate<'a>(
    turns: impl Iterator<Item = &'a PolicyOutcomeEvidence>,
    run: &PolicyOutcomeEvidence,
) -> Result<(), PolicyEvidenceRunProjectorError> {
    let mut terminal = PolicyTerminalOutcome::Succeeded;
    let mut quality = None;
    let mut latency = 0_u64;
    let mut verifier = PolicyVerifierOutcome::NotRun;
    let mut harness_error = false;
    let mut count = 0_u32;
    for turn in turns {
        if terminal_rank(turn.terminal) > terminal_rank(terminal) {
            terminal = turn.terminal;
        }
        quality = if count == 0 {
            turn.quality_micros
        } else {
            quality
                .zip(turn.quality_micros)
                .map(|(left, right)| left.min(right))
        };
        latency = latency.saturating_add(turn.latency_us);
        if verifier_rank(turn.verifier) > verifier_rank(verifier) {
            verifier = turn.verifier;
        }
        harness_error |= turn.harness_error_code.is_some();
        count = count.saturating_add(1);
    }
    if run.terminal != terminal
        || run.quality_micros != quality
        || run.latency_us != latency
        || run.verifier != verifier
        || run.harness_error_code.is_some() != harness_error
    {
        return Err(PolicyEvidenceRunProjectorError::RunAggregateMismatch);
    }
    Ok(())
}

const fn terminal_rank(value: PolicyTerminalOutcome) -> u8 {
    match value {
        PolicyTerminalOutcome::Succeeded => 0,
        PolicyTerminalOutcome::Cancelled => 1,
        PolicyTerminalOutcome::Interrupted => 2,
        PolicyTerminalOutcome::BudgetExhausted => 3,
        PolicyTerminalOutcome::Failed => 4,
    }
}

const fn verifier_rank(value: PolicyVerifierOutcome) -> u8 {
    match value {
        PolicyVerifierOutcome::NotRun => 0,
        PolicyVerifierOutcome::Passed => 1,
        PolicyVerifierOutcome::Cancelled => 2,
        PolicyVerifierOutcome::TestFailure => 3,
        PolicyVerifierOutcome::TimedOut => 4,
        PolicyVerifierOutcome::InfrastructureFailure => 5,
    }
}

const fn terminal_name(value: PolicyTerminalOutcome) -> &'static str {
    match value {
        PolicyTerminalOutcome::Succeeded => "succeeded",
        PolicyTerminalOutcome::Failed => "failed",
        PolicyTerminalOutcome::Cancelled => "cancelled",
        PolicyTerminalOutcome::Interrupted => "interrupted",
        PolicyTerminalOutcome::BudgetExhausted => "budget_exhausted",
    }
}

#[cfg(test)]
mod tests;
