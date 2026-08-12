use iteron_protocol::policy_evidence::PolicyEvidenceError;
use iteron_protocol::slot::SlotId;
use iteron_protocol::{
    PolicyActionId, PolicyDecisionDisposition, PolicyHarnessErrorJoinDigest,
    PolicyHarnessOutcomeId, PolicyOpportunityId, PolicyRuntimeIdentity, PolicyTerminalOutcome,
    PolicyVerifierOutcome, RunId, TurnId,
};

pub(crate) const FROZEN_POLICY_SLOT_COUNT: usize = 9;
pub(crate) const FROZEN_POLICY_SLOT_NAMES: [&str; FROZEN_POLICY_SLOT_COUNT] = [
    "core/context",
    "core/tool_policy",
    "core/memory",
    "core/router",
    "core/planner",
    "core/collaboration",
    "core/scheduler",
    "core/verifier",
    "core/model_router",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum FrozenPolicySlot {
    Context,
    ToolPolicy,
    Memory,
    Router,
    Planner,
    Collaboration,
    Scheduler,
    Verifier,
    ModelRouter,
}

impl FrozenPolicySlot {
    pub(super) fn parse(slot: &SlotId) -> Option<Self> {
        match slot.as_persisted_str() {
            "core/context" => Some(Self::Context),
            "core/tool_policy" => Some(Self::ToolPolicy),
            "core/memory" => Some(Self::Memory),
            "core/router" => Some(Self::Router),
            "core/planner" => Some(Self::Planner),
            "core/collaboration" => Some(Self::Collaboration),
            "core/scheduler" => Some(Self::Scheduler),
            "core/verifier" => Some(Self::Verifier),
            "core/model_router" => Some(Self::ModelRouter),
            _ => None,
        }
    }

    pub(super) const fn name(self) -> &'static str {
        FROZEN_POLICY_SLOT_NAMES[self.index()]
    }

    pub(super) const fn index(self) -> usize {
        match self {
            Self::Context => 0,
            Self::ToolPolicy => 1,
            Self::Memory => 2,
            Self::Router => 3,
            Self::Planner => 4,
            Self::Collaboration => 5,
            Self::Scheduler => 6,
            Self::Verifier => 7,
            Self::ModelRouter => 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrozenSlotPolicyBinding {
    pub slot: SlotId,
    pub policy: PolicyRuntimeIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyOpportunity {
    pub(super) recorder_id: u64,
    pub(super) run_id: RunId,
    pub(super) opportunity_id: PolicyOpportunityId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyDecisionInput {
    pub eligible_actions: Vec<PolicyActionId>,
    pub selected_action: Option<PolicyActionId>,
    pub disposition: PolicyDecisionDisposition,
    pub selected_score_micros: Option<i64>,
    pub propensity_ppm: Option<u32>,
    pub feature_schema_id: String,
    pub feature_digest_sha256: String,
    pub fixed_invariants_digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyOpportunityJoin {
    pub opportunity_count: u32,
    pub opportunities_digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyOutcomeInput {
    pub terminal: PolicyTerminalOutcome,
    pub quality_micros: Option<i64>,
    pub cost_microusd: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub latency_us: u64,
    pub verifier: PolicyVerifierOutcome,
    pub harness_error_code: Option<PolicyHarnessOutcomeId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyRunAggregate {
    pub terminal: PolicyTerminalOutcome,
    pub quality_micros: Option<i64>,
    pub cost_microusd: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub latency_us: u64,
    pub verifier: PolicyVerifierOutcome,
    pub harness_errors: PolicyHarnessErrorJoinDigest,
    pub completed_turns: u32,
}

impl Default for PolicyRunAggregate {
    fn default() -> Self {
        Self {
            terminal: PolicyTerminalOutcome::Succeeded,
            quality_micros: None,
            cost_microusd: Some(0),
            input_tokens: Some(0),
            output_tokens: Some(0),
            latency_us: 0,
            verifier: PolicyVerifierOutcome::NotRun,
            harness_errors: PolicyHarnessErrorJoinDigest::default(),
            completed_turns: 0,
        }
    }
}

#[derive(Debug)]
pub(crate) enum PolicyEvidenceRecorderError {
    Record(iteron_record::RecordError),
    InvalidEvidence(PolicyEvidenceError),
    UnknownSlot(SlotId),
    DuplicateSlot(SlotId),
    MissingSlot(&'static str),
    BundleIdentityMismatch,
    TooManyOpportunities,
    CounterExhausted,
    CrossRunOpportunity,
    CrossRecorderOpportunity,
    UnknownOpportunity(PolicyOpportunityId),
    DuplicateOpportunity(PolicyOpportunityId),
    SelectedActionNotEligible(PolicyActionId),
    PendingOpportunities,
    OutcomeJoinMismatch,
    TurnAlreadyTerminal(TurnId),
    RunAlreadyTerminal,
    MissingTurnOutcome(TurnId),
    ReplayInvariant(&'static str),
}

impl std::fmt::Display for PolicyEvidenceRecorderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Record(_) => formatter.write_str("policy evidence durable append failed"),
            Self::InvalidEvidence(error) => write!(formatter, "invalid policy evidence: {error}"),
            Self::UnknownSlot(slot) => write!(formatter, "unknown frozen policy slot: {}", slot.0),
            Self::DuplicateSlot(slot) => {
                write!(
                    formatter,
                    "duplicate frozen policy slot binding: {}",
                    slot.0
                )
            }
            Self::MissingSlot(slot) => {
                write!(formatter, "missing frozen policy slot binding: {slot}")
            }
            Self::BundleIdentityMismatch => {
                formatter.write_str("policy bindings do not share one immutable bundle identity")
            }
            Self::TooManyOpportunities => formatter.write_str("policy opportunity bound reached"),
            Self::CounterExhausted => formatter.write_str("policy evidence ordinal exhausted"),
            Self::CrossRunOpportunity => {
                formatter.write_str("policy opportunity belongs to another run")
            }
            Self::CrossRecorderOpportunity => {
                formatter.write_str("policy opportunity belongs to another run-local recorder")
            }
            Self::UnknownOpportunity(id) => {
                write!(formatter, "unknown policy opportunity: {}", id.0)
            }
            Self::DuplicateOpportunity(id) => {
                write!(formatter, "policy opportunity already decided: {}", id.0)
            }
            Self::SelectedActionNotEligible(action) => {
                write!(
                    formatter,
                    "selected policy action was not eligible: {}",
                    action.as_str()
                )
            }
            Self::PendingOpportunities => {
                formatter.write_str("scope still has undecided policy opportunities")
            }
            Self::OutcomeJoinMismatch => {
                formatter.write_str("policy outcome count or ordered digest does not match")
            }
            Self::TurnAlreadyTerminal(turn) => {
                write!(
                    formatter,
                    "policy outcome for turn {} is already terminal",
                    turn.0
                )
            }
            Self::RunAlreadyTerminal => {
                formatter.write_str("policy run outcome is already terminal")
            }
            Self::MissingTurnOutcome(turn) => {
                write!(
                    formatter,
                    "turn {} has decisions but no terminal policy outcome",
                    turn.0
                )
            }
            Self::ReplayInvariant(reason) => {
                write!(
                    formatter,
                    "policy evidence replay invariant failed: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for PolicyEvidenceRecorderError {}

impl From<PolicyEvidenceError> for PolicyEvidenceRecorderError {
    fn from(value: PolicyEvidenceError) -> Self {
        Self::InvalidEvidence(value)
    }
}

impl From<iteron_record::RecordError> for PolicyEvidenceRecorderError {
    fn from(value: iteron_record::RecordError) -> Self {
        Self::Record(value)
    }
}

impl PolicyEvidenceRecorderError {
    pub(crate) fn into_record_error(self) -> Result<iteron_record::RecordError, Self> {
        match self {
            Self::Record(error) => Ok(error),
            other => Err(other),
        }
    }
}
