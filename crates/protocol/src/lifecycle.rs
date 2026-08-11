//! Canonical lifecycle vocabulary shared by runtime, records, Hooks and telemetry.
//!
//! This module is descriptive, not authoritative: an owning Session/Turn/Effect/Workflow state
//! machine emits a transition once, and every observer projects that same envelope. Exporters and
//! Hooks must never manufacture state transitions of their own.

mod registry;
pub mod state;

use crate::{EffectId, JobId, RunId, Seq, SessionId, SubagentId, SubmissionId, TurnId, WorkflowId};
use serde::{Deserialize, Serialize};
use std::fmt;

pub use crate::lifecycle::registry::{
    EVENT_COUNT, EVENTS, RESERVED_EVENTS, event_spec, events, is_registered, registered_event_id,
};
pub use crate::lifecycle::state::{
    AgentLoopState, ControlIntent, EffectLifecycleState, JobLifecycleState, LifecycleState,
    ProcessLifecycleState, RunLifecycleState, SessionLifecycleState, SubagentLifecycleState,
    SubmissionLifecycleState, TransitionError, TurnLifecycleState, WorkflowLifecycleState,
};

pub const MAX_LIFECYCLE_EVENT_ID_BYTES: usize = 96;
pub const MAX_LIFECYCLE_CODE_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LifecycleCatalogVersion(pub u16);

pub const LIFECYCLE_CATALOG_VERSION: LifecycleCatalogVersion = LifecycleCatalogVersion(1);

/// A validated stable lower-snake/dot catalog identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LifecycleEventId(String);

impl LifecycleEventId {
    pub fn new(value: impl Into<String>) -> Result<Self, LifecycleIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_LIFECYCLE_EVENT_ID_BYTES {
            return Err(LifecycleIdError);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        }) || !value.contains('.')
        {
            return Err(LifecycleIdError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LifecycleEventId {
    type Error = LifecycleIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LifecycleEventId> for String {
    fn from(value: LifecycleEventId) -> Self {
        value.0
    }
}

impl fmt::Display for LifecycleEventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleIdError;

impl fmt::Display for LifecycleIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("lifecycle id must be a bounded lower-snake/dot identifier")
    }
}

impl std::error::Error for LifecycleIdError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleDomain {
    Context,
    Memory,
    Control,
    ToolProcess,
    ModelProvider,
    Workflow,
    Session,
    Verification,
    HookExporter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePhase {
    Requested,
    Started,
    Progress,
    Decision,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityClass {
    Required,
    Summary,
    FlightRecorderOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookCapability {
    Observe,
    Augment,
    Gate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClass {
    ContentFree,
    SensitiveMetadata,
    Content,
}

/// Sealed, content-free proof for the complete telemetry/debug schema in this catalog build.
///
/// Construction is private and [`content_free_telemetry_schema_proof`] scans the live registry on
/// every request. A future event classified as `Content` or `SensitiveMetadata` therefore removes
/// the proof instead of inheriting an obsolete boolean from an erasure coverage table.
// The private field seals construction to this module. `#[non_exhaustive]` would still permit
// other modules in this crate to forge the proof, so the superficially similar lint fix is weaker.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentFreeTelemetrySchemaProof {
    pub catalog_version: LifecycleCatalogVersion,
    pub event_count: usize,
    _sealed: (),
}

pub fn content_free_telemetry_schema_proof() -> Option<ContentFreeTelemetrySchemaProof> {
    content_free_privacy_proof(events().map(|spec| spec.privacy)).then_some(
        ContentFreeTelemetrySchemaProof {
            catalog_version: LIFECYCLE_CATALOG_VERSION,
            event_count: EVENT_COUNT,
            _sealed: (),
        },
    )
}

fn content_free_privacy_proof(classes: impl IntoIterator<Item = PrivacyClass>) -> bool {
    let mut count = 0usize;
    for class in classes {
        if class != PrivacyClass::ContentFree {
            return false;
        }
        count = count.saturating_add(1);
    }
    count == EVENT_COUNT
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardinalityClass {
    MetricSafe,
    TraceOnly,
    LocalOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportPolicy {
    Always,
    ErrorsAndBenchmarks,
    Sampled,
    LocalOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleEventSpec {
    pub id: &'static str,
    pub schema_version: u16,
    pub domain: LifecycleDomain,
    pub phase: LifecyclePhase,
    pub durability: DurabilityClass,
    pub hook_capability: HookCapability,
    pub privacy: PrivacyClass,
    pub cardinality: CardinalityClass,
    pub default_export: ExportPolicy,
    pub availability: LifecycleAvailability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleAvailability {
    /// A production owner currently has an executable emission path for this transition.
    Active,
    /// The vocabulary is reserved, but the named capability does not currently exist. A runtime
    /// must not manufacture this event merely to make an observability count look complete.
    Reserved(LifecycleReservation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleReservation {
    ContextCapability,
    MemoryCapability,
    EvaluationCapability,
    ProviderRetryCapability,
    SessionFailureCapability,
}

/// Reference to an earlier causal lifecycle event. `ordinal` is local to the owning run/session
/// stream and is not an OTel metric label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEventRef {
    pub event_id: LifecycleEventId,
    pub ordinal: u64,
}

/// Content-free common payload. Domain-specific detail is represented by stable bounded codes and
/// magnitudes, never prompt text, tool arguments, memory text, paths, URLs or arbitrary errors.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magnitude: Option<u64>,
}

impl LifecyclePayload {
    pub fn validate(&self) -> Result<(), LifecyclePayloadError> {
        for value in [&self.outcome_code, &self.reason_code]
            .into_iter()
            .flatten()
        {
            if value.is_empty()
                || value.len() > MAX_LIFECYCLE_CODE_BYTES
                || !value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'.' | b'-')
                })
            {
                return Err(LifecyclePayloadError);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecyclePayloadError;

impl fmt::Display for LifecyclePayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("lifecycle outcome/reason codes must be bounded stable identifiers")
    }
}

impl std::error::Error for LifecyclePayloadError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEventEnvelope {
    pub catalog_version: LifecycleCatalogVersion,
    pub event_id: LifecycleEventId,
    pub event_version: u16,
    pub ordinal: u64,
    pub occurred_at_mono_ns: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<TurnId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_id: Option<SubmissionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<EffectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<WorkflowId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_id: Option<SubagentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<JobId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event: Option<LifecycleEventRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_seq: Option<Seq>,
    #[serde(default)]
    pub payload: LifecyclePayload,
}

impl LifecycleEventEnvelope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.catalog_version != LIFECYCLE_CATALOG_VERSION {
            return Err("unsupported lifecycle catalog version");
        }
        let Some(spec) = event_spec(self.event_id.as_str()) else {
            return Err("unregistered lifecycle event id");
        };
        if self.event_version != spec.schema_version {
            return Err("unsupported lifecycle event schema version");
        }
        self.payload
            .validate()
            .map_err(|_| "invalid lifecycle payload")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_shape_is_exact_and_unique() {
        assert_eq!(EVENT_COUNT, 192);
        let unique = EVENTS
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), EVENT_COUNT);
        assert!(EVENTS.iter().all(|id| LifecycleEventId::new(*id).is_ok()));
    }

    #[test]
    fn hook_capability_allocation_is_exact() {
        let specs = events().collect::<Vec<_>>();
        assert_eq!(
            specs
                .iter()
                .filter(|spec| spec.hook_capability == HookCapability::Gate)
                .count(),
            12
        );
        assert_eq!(
            specs
                .iter()
                .filter(|spec| spec.hook_capability == HookCapability::Augment)
                .count(),
            20
        );
        assert_eq!(
            specs
                .iter()
                .filter(|spec| spec.hook_capability == HookCapability::Observe)
                .count(),
            160
        );
    }

    #[test]
    fn every_telemetry_debug_event_is_content_free_by_schema() {
        let proof = content_free_telemetry_schema_proof().unwrap();
        assert_eq!(proof.event_count, EVENT_COUNT);
        assert_eq!(proof.catalog_version, LIFECYCLE_CATALOG_VERSION);

        // The only free-form-looking fields admit stable identifier characters, not prompt,
        // memory, tool, path, URL, or error text. A debug recorder therefore has no
        // content-bearing derivative to retain outside the private-content graph.
        let payload = LifecyclePayload {
            outcome_code: Some("operator text with spaces".into()),
            ..LifecyclePayload::default()
        };
        assert!(payload.validate().is_err());
        let encoded = serde_json::to_value(LifecyclePayload::default()).unwrap();
        assert!(encoded.as_object().is_some_and(|object| object.is_empty()));

        let mut future = vec![PrivacyClass::ContentFree; EVENT_COUNT];
        future[EVENT_COUNT - 1] = PrivacyClass::Content;
        assert!(
            !content_free_privacy_proof(future),
            "a future content-bearing telemetry schema must remove the absence proof"
        );
    }

    #[test]
    fn every_reserved_event_is_explicit_and_every_other_event_is_active() {
        let reserved = RESERVED_EVENTS
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(reserved.len(), RESERVED_EVENTS.len());
        for spec in events() {
            assert_eq!(
                matches!(spec.availability, LifecycleAvailability::Reserved(_)),
                reserved.contains(spec.id),
                "availability mismatch for {}",
                spec.id
            );
        }
    }
}
