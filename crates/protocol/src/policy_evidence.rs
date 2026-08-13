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
/// The closed action vocabulary consumed by policy-evidence schema v1. Adding an action to an
/// existing slot is a schema change: introduce a new vocabulary type/version instead of accepting
/// an arbitrary string through the v1 constructor.
pub const POLICY_ACTION_VOCABULARY_VERSION: u16 = 1;
pub const MAX_POLICY_ACTIONS: usize = 256;
pub const MAX_POLICY_MACHINE_ID_BYTES: usize = 192;
const ORDERED_OPPORTUNITIES_DOMAIN: &[u8] = b"core-policy-opportunities-v1\0";
const ORDERED_HARNESS_ERRORS_DOMAIN: &[u8] = b"core-policy-harness-errors-v1\0";
const MAX_POLICY_HARNESS_ERRORS: u32 = 1_000_000;

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
        if self.count as usize
            >= iteron_tunables::param_integer(
                "protocol.policy_evidence.max_policy_actions",
                MAX_POLICY_ACTIONS,
            ) * 16
        {
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

/// Closed, content-free action vocabulary for [`PolicyDecisionEvidence`] schema v1.
///
/// These variants describe a strategy decision class. Candidate identities (models, paths,
/// prompts, tool arguments, or memory contents) belong only in bounded feature commitments and
/// must never be encoded into an action label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyActionV1 {
    ContextMaterialize,
    ToolPolicyPureCandidate,
    ToolPolicyEffectCandidate,
    MemoryNoRecall,
    MemoryRecall,
    RouterDirect,
    RouterFanOut,
    PlannerDirectPlan,
    PlannerFanPlan,
    CollaborationBoundedWidth,
    CollaborationSerial,
    SchedulerBoundedPlan,
    SchedulerSinglePermit,
    VerifierStrongWorkspacePlan,
    ModelRouterBoundParentRoute,
    ModelRouterRouteCandidate,
    ModelRouterPreAttestedRoute,
}

impl PolicyActionV1 {
    const fn slot(self) -> &'static str {
        match self {
            Self::ContextMaterialize => "core/context",
            Self::ToolPolicyPureCandidate | Self::ToolPolicyEffectCandidate => "core/tool_policy",
            Self::MemoryNoRecall | Self::MemoryRecall => "core/memory",
            Self::RouterDirect | Self::RouterFanOut => "core/router",
            Self::PlannerDirectPlan | Self::PlannerFanPlan => "core/planner",
            Self::CollaborationBoundedWidth | Self::CollaborationSerial => "core/collaboration",
            Self::SchedulerBoundedPlan | Self::SchedulerSinglePermit => "core/scheduler",
            Self::VerifierStrongWorkspacePlan => "core/verifier",
            Self::ModelRouterBoundParentRoute
            | Self::ModelRouterRouteCandidate
            | Self::ModelRouterPreAttestedRoute => "core/model_router",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContextMaterialize => "materialize",
            Self::ToolPolicyPureCandidate => "pure_candidate",
            Self::ToolPolicyEffectCandidate => "effect_candidate",
            Self::MemoryNoRecall => "no_recall",
            Self::MemoryRecall => "recall",
            Self::RouterDirect => "direct",
            Self::RouterFanOut => "fan_out",
            Self::PlannerDirectPlan => "direct_plan",
            Self::PlannerFanPlan => "fan_plan",
            Self::CollaborationBoundedWidth => "bounded_width",
            Self::CollaborationSerial => "serial",
            Self::SchedulerBoundedPlan => "bounded_plan",
            Self::SchedulerSinglePermit => "single_permit",
            Self::VerifierStrongWorkspacePlan => "strong_workspace_plan",
            Self::ModelRouterBoundParentRoute => "bound_parent_route",
            Self::ModelRouterRouteCandidate => "route_candidate",
            Self::ModelRouterPreAttestedRoute => "pre_attested_route",
        }
    }

    fn parse(slot: &SlotId, value: &str) -> Option<Self> {
        const ACTIONS: [PolicyActionV1; 17] = [
            PolicyActionV1::ContextMaterialize,
            PolicyActionV1::ToolPolicyPureCandidate,
            PolicyActionV1::ToolPolicyEffectCandidate,
            PolicyActionV1::MemoryNoRecall,
            PolicyActionV1::MemoryRecall,
            PolicyActionV1::RouterDirect,
            PolicyActionV1::RouterFanOut,
            PolicyActionV1::PlannerDirectPlan,
            PolicyActionV1::PlannerFanPlan,
            PolicyActionV1::CollaborationBoundedWidth,
            PolicyActionV1::CollaborationSerial,
            PolicyActionV1::SchedulerBoundedPlan,
            PolicyActionV1::SchedulerSinglePermit,
            PolicyActionV1::VerifierStrongWorkspacePlan,
            PolicyActionV1::ModelRouterBoundParentRoute,
            PolicyActionV1::ModelRouterRouteCandidate,
            PolicyActionV1::ModelRouterPreAttestedRoute,
        ];
        ACTIONS
            .into_iter()
            .find(|action| action.slot() == slot.as_persisted_str() && action.as_str() == value)
    }
}

impl PolicyActionId {
    pub fn for_slot(slot: &SlotId, action: PolicyActionV1) -> Result<Self, PolicyEvidenceError> {
        if action.slot() != slot.as_persisted_str() {
            return Err(PolicyEvidenceError::InvalidActionForSlot);
        }
        Ok(Self(action.as_str().to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate_for_slot(&self, slot: &SlotId) -> Result<(), PolicyEvidenceError> {
        PolicyActionV1::parse(slot, &self.0)
            .map(|_| ())
            .ok_or(PolicyEvidenceError::InvalidActionForSlot)
    }
}

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
        if self.eligible_actions.is_empty()
            || self.eligible_actions.len()
                > iteron_tunables::param_integer(
                    "protocol.policy_evidence.max_policy_actions",
                    MAX_POLICY_ACTIONS,
                )
        {
            return Err(PolicyEvidenceError::InvalidActionSet);
        }
        let mut actions = BTreeSet::new();
        for action in &self.eligible_actions {
            action.validate_for_slot(&self.slot)?;
            if !actions.insert(action) {
                return Err(PolicyEvidenceError::InvalidActionSet);
            }
        }
        if let Some(selected) = &self.selected_action {
            selected.validate_for_slot(&self.slot)?;
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

/// Closed, low-cardinality error taxonomy emitted by the runtime. Free-form provider/tool text is
/// never a policy-evidence label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyHarnessErrorCode {
    ProviderError,
    RecordError,
    RouteError,
    ProviderNoticeLimit,
    BudgetError,
    SubmissionError,
    PricingError,
    PermissionError,
    RuntimePolicyError,
    EffectUnknown,
    EffectError,
    IdentityExhausted,
    OpaqueProviderRetries,
    ContextError,
    AgentCatalogError,
    TunablesError,
    ToolingPolicyError,
    ExecutionPolicyError,
    ToolOutputSpillError,
    McpLifecycleError,
    PolicyEvidenceError,
    DelegationError,
    WorkflowError,
    OperatorDrain,
    BudgetMaxTurns,
    BudgetMaxTokens,
    BudgetMaxUsd,
    BudgetMaxWallSecs,
    BudgetVerifyAttempts,
    OperatorInterrupted,
    ConsecutiveToolErrors,
    HarnessFailure,
}

impl PolicyHarnessErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderError => "provider_error",
            Self::RecordError => "record_error",
            Self::RouteError => "route_error",
            Self::ProviderNoticeLimit => "provider_notice_limit",
            Self::BudgetError => "budget_error",
            Self::SubmissionError => "submission_error",
            Self::PricingError => "pricing_error",
            Self::PermissionError => "permission_error",
            Self::RuntimePolicyError => "runtime_policy_error",
            Self::EffectUnknown => "effect_unknown",
            Self::EffectError => "effect_error",
            Self::IdentityExhausted => "identity_exhausted",
            Self::OpaqueProviderRetries => "opaque_provider_retries",
            Self::ContextError => "context_error",
            Self::AgentCatalogError => "agent_catalog_error",
            Self::TunablesError => "tunables_error",
            Self::ToolingPolicyError => "tooling_policy_error",
            Self::ExecutionPolicyError => "execution_policy_error",
            Self::ToolOutputSpillError => "tool_output_spill_error",
            Self::McpLifecycleError => "mcp_lifecycle_error",
            Self::PolicyEvidenceError => "policy_evidence_error",
            Self::DelegationError => "delegation_error",
            Self::WorkflowError => "workflow_error",
            Self::OperatorDrain => "operator_drain",
            Self::BudgetMaxTurns => "budget_max_turns",
            Self::BudgetMaxTokens => "budget_max_tokens",
            Self::BudgetMaxUsd => "budget_max_usd",
            Self::BudgetMaxWallSecs => "budget_max_wall_secs",
            Self::BudgetVerifyAttempts => "budget_verify_attempts",
            Self::OperatorInterrupted => "operator_interrupted",
            Self::ConsecutiveToolErrors => "consecutive_tool_errors",
            Self::HarnessFailure => "harness_failure",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        const CODES: [PolicyHarnessErrorCode; 32] = [
            PolicyHarnessErrorCode::ProviderError,
            PolicyHarnessErrorCode::RecordError,
            PolicyHarnessErrorCode::RouteError,
            PolicyHarnessErrorCode::ProviderNoticeLimit,
            PolicyHarnessErrorCode::BudgetError,
            PolicyHarnessErrorCode::SubmissionError,
            PolicyHarnessErrorCode::PricingError,
            PolicyHarnessErrorCode::PermissionError,
            PolicyHarnessErrorCode::RuntimePolicyError,
            PolicyHarnessErrorCode::EffectUnknown,
            PolicyHarnessErrorCode::EffectError,
            PolicyHarnessErrorCode::IdentityExhausted,
            PolicyHarnessErrorCode::OpaqueProviderRetries,
            PolicyHarnessErrorCode::ContextError,
            PolicyHarnessErrorCode::AgentCatalogError,
            PolicyHarnessErrorCode::TunablesError,
            PolicyHarnessErrorCode::ToolingPolicyError,
            PolicyHarnessErrorCode::ExecutionPolicyError,
            PolicyHarnessErrorCode::ToolOutputSpillError,
            PolicyHarnessErrorCode::McpLifecycleError,
            PolicyHarnessErrorCode::PolicyEvidenceError,
            PolicyHarnessErrorCode::DelegationError,
            PolicyHarnessErrorCode::WorkflowError,
            PolicyHarnessErrorCode::OperatorDrain,
            PolicyHarnessErrorCode::BudgetMaxTurns,
            PolicyHarnessErrorCode::BudgetMaxTokens,
            PolicyHarnessErrorCode::BudgetMaxUsd,
            PolicyHarnessErrorCode::BudgetMaxWallSecs,
            PolicyHarnessErrorCode::BudgetVerifyAttempts,
            PolicyHarnessErrorCode::OperatorInterrupted,
            PolicyHarnessErrorCode::ConsecutiveToolErrors,
            PolicyHarnessErrorCode::HarnessFailure,
        ];
        CODES.into_iter().find(|code| code.as_str() == value)
    }
}

/// A single closed error code, or an order-sensitive commitment to multiple turn errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyHarnessOutcomeId(String);

impl PolicyHarnessOutcomeId {
    pub fn single(code: PolicyHarnessErrorCode) -> Self {
        Self(code.as_str().to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// Revalidate the historical string-shaped wire field at the durable admission boundary.
    pub fn from_persisted(
        value: &str,
        scope: PolicyOutcomeScope,
    ) -> Result<Self, PolicyEvidenceError> {
        let outcome = Self(value.to_owned());
        outcome.validate_for_scope(scope)?;
        Ok(outcome)
    }

    /// Return the closed turn-level code carried by this outcome. Aggregate run outcomes do not
    /// have a single code and therefore return `None`.
    pub fn single_code(&self) -> Option<PolicyHarnessErrorCode> {
        PolicyHarnessErrorCode::parse(&self.0)
    }

    fn multiple(count: u32, digest: &[u8; 32]) -> Self {
        Self(format!("multiple:{count}:{}", encode_lower_hex(digest)))
    }

    fn validate_for_scope(&self, scope: PolicyOutcomeScope) -> Result<(), PolicyEvidenceError> {
        if self.single_code().is_some() {
            return Ok(());
        }
        if scope != PolicyOutcomeScope::Run {
            return Err(PolicyEvidenceError::InvalidHarnessOutcome);
        }
        let mut parts = self.0.split(':');
        let valid = parts.next() == Some("multiple")
            && parts
                .next()
                .and_then(|count| count.parse::<u32>().ok())
                .is_some_and(|count| {
                    (2..=iteron_tunables::param_integer(
                        "protocol.policy_evidence.max_policy_harness_errors",
                        MAX_POLICY_HARNESS_ERRORS,
                    ))
                        .contains(&count)
                })
            && parts
                .next()
                .is_some_and(|digest| validate_digest(digest).is_ok())
            && parts.next().is_none();
        valid
            .then_some(())
            .ok_or(PolicyEvidenceError::InvalidHarnessOutcome)
    }
}

/// Shared order-sensitive aggregate used by the live writer, replay, and offline projector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyHarnessErrorJoinDigest {
    count: u32,
    digest: [u8; 32],
    first: Option<PolicyHarnessErrorCode>,
}

impl Default for PolicyHarnessErrorJoinDigest {
    fn default() -> Self {
        Self {
            count: 0,
            digest: Sha256::digest(ORDERED_HARNESS_ERRORS_DOMAIN).into(),
            first: None,
        }
    }
}

impl PolicyHarnessErrorJoinDigest {
    pub fn append(&mut self, code: PolicyHarnessErrorCode) -> Result<(), PolicyEvidenceError> {
        if self.count
            >= iteron_tunables::param_integer(
                "protocol.policy_evidence.max_policy_harness_errors",
                MAX_POLICY_HARNESS_ERRORS,
            )
        {
            return Err(PolicyEvidenceError::TooManyHarnessErrors);
        }
        let mut hasher = Sha256::new();
        hasher.update(ORDERED_HARNESS_ERRORS_DOMAIN);
        hasher.update(self.digest);
        hasher.update(self.count.to_le_bytes());
        hasher.update(code.as_str().as_bytes());
        self.digest = hasher.finalize().into();
        self.first.get_or_insert(code);
        self.count += 1;
        Ok(())
    }

    pub fn outcome(&self) -> Option<PolicyHarnessOutcomeId> {
        match (self.count, self.first) {
            (0, _) => None,
            (1, Some(code)) => Some(PolicyHarnessOutcomeId::single(code)),
            (_, Some(_)) => Some(PolicyHarnessOutcomeId::multiple(self.count, &self.digest)),
            (_, None) => None,
        }
    }
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
        if self.opportunity_count as usize
            > iteron_tunables::param_integer(
                "protocol.policy_evidence.max_policy_actions",
                MAX_POLICY_ACTIONS,
            ) * 16
        {
            return Err(PolicyEvidenceError::TooManyOpportunities);
        }
        if let Some(code) = &self.harness_error_code {
            PolicyHarnessOutcomeId::from_persisted(code, self.scope)?;
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
    InvalidActionForSlot,
    InvalidSelection,
    InvalidPropensity,
    InvalidOutcomeScope,
    InvalidHarnessOutcome,
    TooManyOpportunities,
    TooManyHarnessErrors,
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
            Self::InvalidActionForSlot => {
                "policy action is not in the closed vocabulary for its strategy slot"
            }
            Self::InvalidSelection => "selected action and decision disposition disagree",
            Self::InvalidPropensity => "propensity is outside 1..=1,000,000 ppm",
            Self::InvalidOutcomeScope => "turn/run outcome scope and turn identity disagree",
            Self::InvalidHarnessOutcome => {
                "harness outcome is outside the closed error taxonomy or aggregate format"
            }
            Self::TooManyOpportunities => "outcome opportunity count exceeds its bound",
            Self::TooManyHarnessErrors => "harness-error aggregate count exceeds its bound",
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
        && value.len()
            <= iteron_tunables::param_integer(
                "protocol.policy_evidence.max_policy_machine_id_bytes",
                MAX_POLICY_MACHINE_ID_BYTES,
            )
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
            eligible_actions: vec![
                PolicyActionId::for_slot(
                    &SlotId("core/router".into()),
                    PolicyActionV1::RouterDirect,
                )
                .unwrap(),
            ],
            selected_action: Some(
                PolicyActionId::for_slot(
                    &SlotId("core/router".into()),
                    PolicyActionV1::RouterDirect,
                )
                .unwrap(),
            ),
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
            Err(PolicyEvidenceError::InvalidActionForSlot)
        );

        evidence.selected_action = Some(PolicyActionId("/private/operator-prompt".into()));
        assert_eq!(
            evidence.validate(),
            Err(PolicyEvidenceError::InvalidActionForSlot)
        );
        assert_eq!(
            PolicyActionId::for_slot(&SlotId("core/router".into()), PolicyActionV1::MemoryRecall,),
            Err(PolicyEvidenceError::InvalidActionForSlot)
        );
    }

    #[test]
    fn outcome_scope_is_joinable_and_content_free() {
        let mut outcome = PolicyOutcomeEvidence {
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
        outcome.harness_error_code = Some("/private/operator-prompt".into());
        assert_eq!(
            outcome.validate(),
            Err(PolicyEvidenceError::InvalidHarnessOutcome)
        );
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

    #[test]
    fn harness_outcome_is_closed_and_run_aggregate_is_order_sensitive() {
        let mut left = PolicyHarnessErrorJoinDigest::default();
        left.append(PolicyHarnessErrorCode::ProviderError).unwrap();
        left.append(PolicyHarnessErrorCode::RecordError).unwrap();
        let mut right = PolicyHarnessErrorJoinDigest::default();
        right.append(PolicyHarnessErrorCode::RecordError).unwrap();
        right.append(PolicyHarnessErrorCode::ProviderError).unwrap();
        assert_ne!(left.outcome(), right.outcome());

        let aggregate = left.outcome().unwrap();
        assert_eq!(aggregate.single_code(), None);
        assert_eq!(
            aggregate.validate_for_scope(PolicyOutcomeScope::Run),
            Ok(())
        );
        assert_eq!(
            aggregate.validate_for_scope(PolicyOutcomeScope::Turn),
            Err(PolicyEvidenceError::InvalidHarnessOutcome)
        );

        let arbitrary = PolicyHarnessOutcomeId("/private/operator-prompt".into());
        assert_eq!(
            arbitrary.validate_for_scope(PolicyOutcomeScope::Run),
            Err(PolicyEvidenceError::InvalidHarnessOutcome)
        );
    }
}
