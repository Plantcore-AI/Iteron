//! Content-free, joinable evidence for trainable harness decisions.
//!
//! This vocabulary carries identities, bounded action labels, fixed-point scores, and aggregate
//! outcomes only. Prompt text, source, paths, memory, tool arguments, and provider payloads have no
//! field in the schema.

use crate::slot::SlotId;
use crate::{RunId, TurnId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const POLICY_DECISION_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const MAX_POLICY_ACTIONS: usize = 256;
pub const MAX_POLICY_MACHINE_ID_BYTES: usize = 192;
const ORDERED_OPPORTUNITIES_DOMAIN: &[u8] = b"core-policy-opportunities-v1\0";

/// Canonical, order-sensitive commitment shared by the live recorder and offline projection.
/// Keeping the algorithm in the protocol prevents a trajectory projector from accepting a join
/// that the durable writer would have rejected (or vice versa).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOpportunityJoinDigest {
    count: u32,
    digest: [u8; 32],
}

impl Default for PolicyOpportunityJoinDigest {
    fn default() -> Self {
        Self {
            count: 0,
            digest: Sha256::digest(ORDERED_OPPORTUNITIES_DOMAIN).into(),
        }
    }
}

impl PolicyOpportunityJoinDigest {
    pub fn append(&mut self, opportunity: &PolicyOpportunityId) -> Result<(), PolicyEvidenceError> {
        if self.count as usize >= MAX_POLICY_ACTIONS * 16 {
            return Err(PolicyEvidenceError::TooManyOpportunities);
        }
        let mut hasher = Sha256::new();
        hasher.update(ORDERED_OPPORTUNITIES_DOMAIN);
        hasher.update(self.digest);
        hasher.update(self.count.to_le_bytes());
        hasher.update((opportunity.0.len() as u64).to_le_bytes());
        hasher.update(opportunity.0.as_bytes());
        self.digest = hasher.finalize().into();
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn digest_sha256(&self) -> String {
        encode_lower_hex(&self.digest)
    }

    pub fn matches(&self, evidence: &PolicyOutcomeEvidence) -> bool {
        evidence.opportunity_count == self.count
            && evidence.opportunities_digest_sha256 == self.digest_sha256()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyOpportunityId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyActionId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuntimeIdentity {
    pub bundle_id: String,
    pub bundle_digest_sha256: String,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_digest_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionDisposition {
    Selected,
    Abstained,
    BaselineFallback,
}

/// One and only one selection record for one live strategy opportunity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionEvidence {
    pub schema_version: u16,
    pub opportunity_id: PolicyOpportunityId,
    pub run_id: RunId,
    pub turn_id: Option<TurnId>,
    pub slot: SlotId,
    pub policy: PolicyRuntimeIdentity,
    pub eligible_actions: Vec<PolicyActionId>,
    pub selected_action: Option<PolicyActionId>,
    pub disposition: PolicyDecisionDisposition,
    /// Selected-action score in millionths. Negative values are allowed for logits/utilities.
    pub selected_score_micros: Option<i64>,
    /// Selection probability in parts per million; `1..=1_000_000` when present.
    pub propensity_ppm: Option<u32>,
    pub feature_schema_id: String,
    pub feature_digest_sha256: String,
    pub fixed_invariants_digest_sha256: String,
    pub tunables_digest_sha256: String,
    /// Contiguous ordinal owned by the run-local decision recorder.
    pub decision_ordinal: u64,
    /// Monotonic time from the run writer's segment origin, never a wall-clock authority.
    pub decided_at_us: u64,
}

impl PolicyDecisionEvidence {
    pub fn validate(&self) -> Result<(), PolicyEvidenceError> {
        if self.schema_version != POLICY_DECISION_EVIDENCE_SCHEMA_VERSION {
            return Err(PolicyEvidenceError::UnsupportedSchema);
        }
        validate_machine_id("opportunity_id", &self.opportunity_id.0)?;
        validate_machine_id("run_id", &self.run_id.0)?;
        self.slot
            .validate()
            .map_err(|_| PolicyEvidenceError::InvalidMachineId("slot"))?;
        self.policy.validate()?;
        validate_machine_id("feature_schema_id", &self.feature_schema_id)?;
        for digest in [
            &self.feature_digest_sha256,
            &self.fixed_invariants_digest_sha256,
            &self.tunables_digest_sha256,
        ] {
            validate_digest(digest)?;
        }
        if self.eligible_actions.is_empty() || self.eligible_actions.len() > MAX_POLICY_ACTIONS {
            return Err(PolicyEvidenceError::InvalidActionSet);
        }
        let mut actions = BTreeSet::new();
        for action in &self.eligible_actions {
            validate_machine_id("action_id", &action.0)?;
            if !actions.insert(action) {
                return Err(PolicyEvidenceError::InvalidActionSet);
            }
        }
        match self.disposition {
            PolicyDecisionDisposition::Selected => {
                let selected = self
                    .selected_action
                    .as_ref()
                    .ok_or(PolicyEvidenceError::InvalidSelection)?;
                if !actions.contains(selected) {
                    return Err(PolicyEvidenceError::InvalidSelection);
                }
            }
            PolicyDecisionDisposition::Abstained | PolicyDecisionDisposition::BaselineFallback
                if self.selected_action.is_some() =>
            {
                return Err(PolicyEvidenceError::InvalidSelection);
            }
            PolicyDecisionDisposition::Abstained | PolicyDecisionDisposition::BaselineFallback => {}
        }
        if self
            .propensity_ppm
            .is_some_and(|value| value == 0 || value > 1_000_000)
        {
            return Err(PolicyEvidenceError::InvalidPropensity);
        }
        Ok(())
    }
}

impl PolicyRuntimeIdentity {
    pub fn validate(&self) -> Result<(), PolicyEvidenceError> {
        for (field, value) in [
            ("bundle_id", self.bundle_id.as_str()),
            ("policy_id", self.policy_id.as_str()),
            ("policy_version", self.policy_version.as_str()),
        ] {
            validate_machine_id(field, value)?;
        }
        validate_digest(&self.bundle_digest_sha256)?;
        validate_digest(&self.policy_digest_sha256)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcomeScope {
    Turn,
    Run,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTerminalOutcome {
    Succeeded,
    Failed,
    Cancelled,
    Interrupted,
    BudgetExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerifierOutcome {
    NotRun,
    Passed,
    TestFailure,
    TimedOut,
    InfrastructureFailure,
    Cancelled,
}

/// Aggregate terminal truth joined to selections by `(run_id, turn_id)` and a commitment to the
/// exact ordered opportunity identities observed in that scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOutcomeEvidence {
    pub schema_version: u16,
    pub scope: PolicyOutcomeScope,
    pub run_id: RunId,
    pub turn_id: Option<TurnId>,
    pub terminal: PolicyTerminalOutcome,
    pub opportunity_count: u32,
    pub opportunities_digest_sha256: String,
    pub quality_micros: Option<i64>,
    pub cost_microusd: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub latency_us: u64,
    pub verifier: PolicyVerifierOutcome,
    pub harness_error_code: Option<String>,
    pub outcome_ordinal: u64,
}

impl PolicyOutcomeEvidence {
    pub fn validate(&self) -> Result<(), PolicyEvidenceError> {
        if self.schema_version != POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION {
            return Err(PolicyEvidenceError::UnsupportedSchema);
        }
        validate_machine_id("run_id", &self.run_id.0)?;
        match (self.scope, self.turn_id) {
            (PolicyOutcomeScope::Turn, None) | (PolicyOutcomeScope::Run, Some(_)) => {
                return Err(PolicyEvidenceError::InvalidOutcomeScope);
            }
            (PolicyOutcomeScope::Turn, Some(_)) | (PolicyOutcomeScope::Run, None) => {}
        }
        validate_digest(&self.opportunities_digest_sha256)?;
        if self.opportunity_count as usize > MAX_POLICY_ACTIONS * 16 {
            return Err(PolicyEvidenceError::TooManyOpportunities);
        }
        if let Some(code) = &self.harness_error_code {
            validate_machine_id("harness_error_code", code)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEvidenceError {
    UnsupportedSchema,
    InvalidMachineId(&'static str),
    InvalidDigest,
    InvalidActionSet,
    InvalidSelection,
    InvalidPropensity,
    InvalidOutcomeScope,
    TooManyOpportunities,
}

impl std::fmt::Display for PolicyEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::UnsupportedSchema => "unsupported policy evidence schema",
            Self::InvalidMachineId(field) => {
                return write!(formatter, "invalid bounded machine identifier in {field}");
            }
            Self::InvalidDigest => "invalid lowercase SHA-256 digest",
            Self::InvalidActionSet => {
                "eligible action set is empty, duplicated, or outside its bound"
            }
            Self::InvalidSelection => "selected action and decision disposition disagree",
            Self::InvalidPropensity => "propensity is outside 1..=1,000,000 ppm",
            Self::InvalidOutcomeScope => "turn/run outcome scope and turn identity disagree",
            Self::TooManyOpportunities => "outcome opportunity count exceeds its bound",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PolicyEvidenceError {}

fn validate_digest(value: &str) -> Result<(), PolicyEvidenceError> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    valid
        .then_some(())
        .ok_or(PolicyEvidenceError::InvalidDigest)
}

fn validate_machine_id(field: &'static str, value: &str) -> Result<(), PolicyEvidenceError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_POLICY_MACHINE_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'+')
        });
    valid
        .then_some(())
        .ok_or(PolicyEvidenceError::InvalidMachineId(field))
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> PolicyRuntimeIdentity {
        PolicyRuntimeIdentity {
            bundle_id: "iteron:baseline".into(),
            bundle_digest_sha256: "a".repeat(64),
            policy_id: "iteron://policies/router/baseline-v1".into(),
            policy_version: "1.0.0".into(),
            policy_digest_sha256: "b".repeat(64),
        }
    }

    #[test]
    fn decision_requires_a_bounded_selected_eligible_action() {
        let mut evidence = PolicyDecisionEvidence {
            schema_version: POLICY_DECISION_EVIDENCE_SCHEMA_VERSION,
            opportunity_id: PolicyOpportunityId("route:0".into()),
            run_id: RunId("run-1".into()),
            turn_id: Some(TurnId(1)),
            slot: SlotId("core/router".into()),
            policy: identity(),
            eligible_actions: vec![PolicyActionId("direct".into())],
            selected_action: Some(PolicyActionId("direct".into())),
            disposition: PolicyDecisionDisposition::Selected,
            selected_score_micros: None,
            propensity_ppm: Some(1_000_000),
            feature_schema_id: "iteron:router-features-v1".into(),
            feature_digest_sha256: "c".repeat(64),
            fixed_invariants_digest_sha256: "d".repeat(64),
            tunables_digest_sha256: "e".repeat(64),
            decision_ordinal: 0,
            decided_at_us: 1,
        };
        assert_eq!(evidence.validate(), Ok(()));
        evidence.selected_action = Some(PolicyActionId("orchestrated".into()));
        assert_eq!(
            evidence.validate(),
            Err(PolicyEvidenceError::InvalidSelection)
        );
    }

    #[test]
    fn outcome_scope_is_joinable_and_content_free() {
        let outcome = PolicyOutcomeEvidence {
            schema_version: POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION,
            scope: PolicyOutcomeScope::Turn,
            run_id: RunId("run-1".into()),
            turn_id: Some(TurnId(1)),
            terminal: PolicyTerminalOutcome::Succeeded,
            opportunity_count: 1,
            opportunities_digest_sha256: "f".repeat(64),
            quality_micros: None,
            cost_microusd: Some(42),
            input_tokens: Some(100),
            output_tokens: Some(10),
            latency_us: 123,
            verifier: PolicyVerifierOutcome::Passed,
            harness_error_code: None,
            outcome_ordinal: 0,
        };
        assert_eq!(outcome.validate(), Ok(()));
        let encoded = serde_json::to_string(&outcome).unwrap();
        for forbidden in ["prompt", "source", "path", "memory", "arguments"] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn opportunity_join_is_order_sensitive_and_matches_outcome() {
        let mut left = PolicyOpportunityJoinDigest::default();
        left.append(&PolicyOpportunityId("route:0".into())).unwrap();
        left.append(&PolicyOpportunityId("tool:1".into())).unwrap();
        let mut right = PolicyOpportunityJoinDigest::default();
        right.append(&PolicyOpportunityId("tool:1".into())).unwrap();
        right
            .append(&PolicyOpportunityId("route:0".into()))
            .unwrap();
        assert_ne!(left.digest_sha256(), right.digest_sha256());

        let mut evidence = PolicyOutcomeEvidence {
            schema_version: POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION,
            scope: PolicyOutcomeScope::Run,
            run_id: RunId("run-1".into()),
            turn_id: None,
            terminal: PolicyTerminalOutcome::Succeeded,
            opportunity_count: left.count(),
            opportunities_digest_sha256: left.digest_sha256(),
            quality_micros: None,
            cost_microusd: None,
            input_tokens: None,
            output_tokens: None,
            latency_us: 0,
            verifier: PolicyVerifierOutcome::NotRun,
            harness_error_code: None,
            outcome_ordinal: 0,
        };
        assert!(left.matches(&evidence));
        evidence.opportunity_count += 1;
        assert!(!left.matches(&evidence));
    }
}
