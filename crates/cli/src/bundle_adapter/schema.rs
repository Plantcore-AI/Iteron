use serde::{Deserialize, Serialize};

pub(crate) const COMPILED_BUNDLE_SCHEMA_VERSION: u16 = 1;
pub(crate) const IMPLEMENTATION_ARTIFACT_SCHEMA_VERSION: u16 = 1;
pub(crate) const MAX_IMPLEMENTATION_ARTIFACT_BYTES: usize = 2 * 1024;
pub(crate) const MAX_REGISTERED_IMPLEMENTATIONS: usize = 32;

/// The complete set of production strategy ports owned by the CLI composition root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreSlot {
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

impl CoreSlot {
    pub(crate) const ALL: [Self; 9] = [
        Self::Context,
        Self::ToolPolicy,
        Self::Memory,
        Self::Router,
        Self::Planner,
        Self::Collaboration,
        Self::Scheduler,
        Self::Verifier,
        Self::ModelRouter,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Context => "core/context",
            Self::ToolPolicy => "core/tool_policy",
            Self::Memory => "core/memory",
            Self::Router => "core/router",
            Self::Planner => "core/planner",
            Self::Collaboration => "core/collaboration",
            Self::Scheduler => "core/scheduler",
            Self::Verifier => "core/verifier",
            Self::ModelRouter => "core/model_router",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImplementationFlavor {
    Baseline,
    Alternative,
}

/// Canonical bytes hashed by the implementation registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImplementationArtifact {
    pub schema_version: u16,
    pub slot: String,
    pub policy_id: String,
    pub version: String,
    pub implementation: String,
}

/// Content-free catalog projection suitable for operator diagnostics and config generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ImplementationIdentity {
    pub slot: String,
    pub policy_id: String,
    pub version: String,
    pub digest: String,
    pub implementation: String,
    pub artifact_bytes: u32,
    pub baseline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SlotReceiptStatus {
    Applied,
    Baseline,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RejectionCode {
    MalformedBundle,
    DuplicateSlot,
    UnknownSlot,
    UnknownImplementation,
    UnknownVersion,
    DigestMismatch,
    MalformedArtifact,
    DuplicateImplementation,
    RegistryBoundExceeded,
    WrongImplementationSlot,
    AtomicBundleRejected,
    ProjectSelectionForbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BundleCoverage {
    Baseline,
    Partial,
    Full,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SlotCompilationReceipt {
    pub slot: String,
    pub status: SlotReceiptStatus,
    pub requested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub implementation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection: Option<RejectionCode>,
}

impl SlotCompilationReceipt {
    pub(crate) fn baseline(
        slot: CoreSlot,
        policy_id: String,
        version: String,
        digest: String,
        implementation: String,
    ) -> Self {
        Self {
            slot: slot.as_str().to_owned(),
            status: SlotReceiptStatus::Baseline,
            requested: false,
            policy_id: Some(policy_id),
            version: Some(version),
            digest: Some(digest),
            implementation,
            rejection: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BundleCompilationReceipt {
    pub schema_version: u16,
    pub bundle_id: Option<String>,
    pub bundle_digest: Option<String>,
    pub coverage: BundleCoverage,
    /// Always in [`CoreSlot::ALL`] order, independent of input policy order.
    pub slots: Vec<SlotCompilationReceipt>,
    /// One stable entry per refused request, including duplicate and non-core slots that cannot
    /// occupy one of the fixed slot rows above.
    pub rejected_requests: Vec<RejectedPolicyReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RejectedPolicyReceipt {
    pub slot: String,
    pub policy_id: String,
    pub version: String,
    pub digest: String,
    pub rejection: RejectionCode,
}

impl BundleCompilationReceipt {
    pub(crate) fn baseline(slots: Vec<SlotCompilationReceipt>) -> Self {
        Self {
            schema_version: COMPILED_BUNDLE_SCHEMA_VERSION,
            bundle_id: None,
            bundle_digest: None,
            coverage: BundleCoverage::Baseline,
            slots,
            rejected_requests: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleCompileFailure {
    pub code: RejectionCode,
    pub receipt: BundleCompilationReceipt,
}

impl std::fmt::Display for BundleCompileFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "operator policy bundle compilation was rejected: {:?}",
            self.code
        )
    }
}

impl std::error::Error for BundleCompileFailure {}
