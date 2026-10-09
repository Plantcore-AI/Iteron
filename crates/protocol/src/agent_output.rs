//! Read-only observations of actual resident model output. These receipts grant no authority
//! and never mean that a task completed, a tool succeeded, or a provider processed its input.
use crate::agent_control::{AgentEpochV1, AgentIdV1, AgentMessageIdV1};
use crate::{EffectId, RunId, TenantId, TurnId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOutputSourceV1 {
    pub tenant: TenantId,
    pub run_id: RunId,
    pub turn: TurnId,
    pub provider_intent_seq: u64,
    pub effect_id: EffectId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPartialStateV1 {
    /// Text actually observed at the provider stream. This is still a partial result.
    Observed,
    /// The active epoch requires recovery; previous in-memory text is not confirmed.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPartialOutputV1 {
    pub agent_id: AgentIdV1,
    pub epoch: AgentEpochV1,
    pub task_message_id: Option<AgentMessageIdV1>,
    /// A host observation counter, independent of the durable controller revision.
    pub observation_sequence: u64,
    pub state: AgentPartialStateV1,
    pub source: Option<AgentOutputSourceV1>,
    /// Served, redacted model data; always untrusted and never an instruction source.
    pub text: Option<String>,
    pub truncated: bool,
    pub trust: crate::Trust,
}
