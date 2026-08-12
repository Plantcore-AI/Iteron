use iteron_protocol::Effort;
use iteron_tunables::{ExternalCeiling, RuntimeResolutionError};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChildToolDisposition {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentMemoryMode {
    Isolated,
    SharedRead,
    SharedReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AgentMemoryScopeObservation {
    pub mode: AgentMemoryMode,
    pub scope_id: Option<String>,
    pub inherit_parent: bool,
}

/// The already-resolved child overlay consumed by the worker launcher. This is intentionally not
/// an `AgentDef`: catalog intent is narrowed and routed again before it becomes executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ChildOverlayObservation {
    pub agent_name: String,
    pub provider_id: String,
    pub model_id: String,
    pub effort: Effort,
    pub tool_profile: BTreeMap<String, ChildToolDisposition>,
    pub memory_scope: Option<AgentMemoryScopeObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum McpTransport {
    Stdio,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MessagingTopology {
    ParentMediated,
    Peer,
    Broadcast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OAuthLifecycleMode {
    Disabled,
    Bearer,
    RefreshToken,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SessionIsolationProfile {
    Hermetic,
    Durable,
    Interactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct ReplayOwnerObservation {
    pub verify_hash_chain: bool,
    pub verify_identity_scope: bool,
    pub verify_effect_terminals: bool,
    pub fail_closed: bool,
}

/// Independent authority domains. `None` means the authority owner did not expose a fact; an
/// empty set means it explicitly admits no value. Neither state is reconstructed from a candidate.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ExtensionAuthorityFacts<'a> {
    pub run_session_spawn_cap: Option<usize>,
    pub verification_minimum_evidence: Option<usize>,
    pub parent_cost_model_routes: Option<&'a BTreeSet<String>>,
    pub operator_tool_profiles: Option<&'a [BTreeMap<String, ChildToolDisposition>]>,
    pub tenant_memory_scope_ids: Option<&'a BTreeSet<String>>,
    pub operator_messaging_topologies: Option<&'a BTreeSet<MessagingTopology>>,
    pub operator_mcp_transports: Option<&'a BTreeSet<McpTransport>>,
    pub operator_oauth_modes: Option<&'a BTreeSet<OAuthLifecycleMode>>,
    pub operator_session_profiles: Option<&'a BTreeSet<SessionIsolationProfile>>,
    pub tenant_session_profiles: Option<&'a BTreeSet<SessionIsolationProfile>>,
    pub benchmark_replay_policy: Option<ReplayOwnerObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FactLayer {
    Implementation,
    Default,
    Activation,
    Constraint {
        field: &'static str,
        ceiling: ExternalCeiling,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GapImpact {
    /// The family is active (or always-on), so composition must not describe the checkpoint as
    /// resolved while this gap remains.
    Blocking,
    /// The missing behavior is not active for this composition.
    Inactive,
    /// The canonical registry marks the family unavailable.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ExtensionGapReason {
    RegistryUnavailable,
    RegistryUnavailableOwnerPresent,
    OwnerGetterMissing,
    OwnerSchemaMismatch,
    RequiredOwnerObservationMissing,
    CapabilityNotAttested,
    IndependentAuthorityMissing,
    ExternalCeilingBelowSchemaMinimum,
    ConstraintUnitMismatch,
    MixedMcpTransportsNotScalar,
    WorkflowCapIsNotSessionCap,
    StartupDeadlineCollapsesStdioHttp,
    ToolDeadlineCollapsesStdioHttp,
    OAuthSchemaMismatch,
    SpillPolicyCannotExpressRejectOnlyOwner,
    ExposureSchemaCannotExpressLazyDiscovery,
    WaitAllReducerHasNoEarlyStop,
}

impl ExtensionGapReason {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::RegistryUnavailable => "registry_unavailable",
            Self::RegistryUnavailableOwnerPresent => "registry_unavailable_owner_present",
            Self::OwnerGetterMissing => "owner_getter_missing",
            Self::OwnerSchemaMismatch => "owner_schema_mismatch",
            Self::RequiredOwnerObservationMissing => "required_owner_observation_missing",
            Self::CapabilityNotAttested => "capability_not_attested",
            Self::IndependentAuthorityMissing => "independent_authority_missing",
            Self::ExternalCeilingBelowSchemaMinimum => "external_ceiling_below_schema_minimum",
            Self::ConstraintUnitMismatch => "constraint_unit_mismatch",
            Self::MixedMcpTransportsNotScalar => "mixed_mcp_transports_not_scalar",
            Self::WorkflowCapIsNotSessionCap => "workflow_cap_is_not_session_cap",
            Self::StartupDeadlineCollapsesStdioHttp => "startup_deadline_collapses_stdio_http",
            Self::ToolDeadlineCollapsesStdioHttp => "tool_deadline_collapses_stdio_http",
            Self::OAuthSchemaMismatch => "oauth_schema_mismatch",
            Self::SpillPolicyCannotExpressRejectOnlyOwner => {
                "spill_policy_cannot_express_reject_only_owner"
            }
            Self::ExposureSchemaCannotExpressLazyDiscovery => {
                "exposure_schema_cannot_express_lazy_discovery"
            }
            Self::WaitAllReducerHasNoEarlyStop => "wait_all_reducer_has_no_early_stop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExtensionFactGap {
    pub ordinal: u16,
    pub family_id: &'static str,
    pub layer: FactLayer,
    pub reason: ExtensionGapReason,
    pub impact: GapImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AppliedExtensionFact {
    pub ordinal: u16,
    pub family_id: &'static str,
    pub layer: FactLayer,
}

#[derive(Debug, Default)]
pub(crate) struct ExtensionFactsReport {
    pub applied: Vec<AppliedExtensionFact>,
    pub gaps: Vec<ExtensionFactGap>,
}

impl ExtensionFactsReport {
    pub(super) fn mark(&mut self, ordinal: u16, family_id: &'static str, layer: FactLayer) {
        self.applied.push(AppliedExtensionFact {
            ordinal,
            family_id,
            layer,
        });
    }

    pub(super) fn gap(
        &mut self,
        ordinal: u16,
        family_id: &'static str,
        layer: FactLayer,
        reason: ExtensionGapReason,
        impact: GapImpact,
    ) {
        self.gaps.push(ExtensionFactGap {
            ordinal,
            family_id,
            layer,
            reason,
            impact,
        });
    }

    pub(crate) fn is_resolution_blocked(&self) -> bool {
        self.gaps
            .iter()
            .any(|gap| gap.impact == GapImpact::Blocking)
    }

    pub(crate) fn blocking_gaps(&self) -> impl Iterator<Item = &ExtensionFactGap> {
        self.gaps
            .iter()
            .filter(|gap| gap.impact == GapImpact::Blocking)
    }

    pub(super) fn finish(&mut self) {
        self.applied.sort_unstable();
        self.applied.dedup();
        self.gaps.sort_unstable();
        self.gaps.dedup();
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExtensionFactError {
    #[error("the child overlay belongs to another provider/model route")]
    ChildRouteIdentityMismatch,
    #[error("the child overlay exceeds the bounded registry value shape")]
    InvalidChildOverlay,
    #[error("the supplied run budget is invalid")]
    InvalidBudget,
    #[error("runtime owner value for `{0}` exceeds the registry integer representation")]
    IntegerOverflow(&'static str),
    #[error("extension-owner evidence could not be encoded")]
    EvidenceEncoding,
    #[error(transparent)]
    Resolution(#[from] RuntimeResolutionError),
}
