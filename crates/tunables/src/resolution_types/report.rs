use super::{EvidenceSubject, ResolutionValue, RouteIdentity};
use crate::{
    BenchmarkRelevance, CapabilityRequirement, CoreStrategySlot, DefaultSpec, ExternalCeiling,
    InactiveReason, OptimizationSpec, ProviderRequirement, SourceKind, SourceTrust,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResolutionSource {
    Declared {
        kind: SourceKind,
        trust: SourceTrust,
        declared_locator: &'static str,
        evidence_digest_sha256: String,
    },
    Profile {
        kind: SourceKind,
        trust: SourceTrust,
        declared_locator: &'static str,
        profile_digest_sha256: String,
    },
    Default {
        resolver_id: String,
        evidence_digest_sha256: Option<String>,
        subject: Option<EvidenceSubject>,
        fallback: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolutionProvenance {
    pub source: ResolutionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjustmentKind {
    ClampMaximum,
    ProviderDegrade,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Adjustment {
    pub kind: AdjustmentKind,
    pub field: String,
    pub requested: ResolutionValue,
    pub effective: ResolutionValue,
    pub ceiling: ExternalCeiling,
    pub policy_id: &'static str,
    pub evidence_digest_sha256: String,
    pub subject: EvidenceSubject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShadowedValue {
    pub value: ResolutionValue,
    pub provenance: ResolutionProvenance,
    pub reason_code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UnresolvedReason {
    ResolverEvidenceMissing {
        resolver_id: String,
    },
    ResolverReturnedAbsent {
        resolver_id: String,
        code: String,
    },
    ResolverUnsupported {
        resolver_id: String,
        code: String,
    },
    ExternalConstraintMissing {
        field: String,
        ceiling: ExternalCeiling,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InactiveCause {
    Activation {
        reason: InactiveReason,
    },
    RuntimeSeamMissing {
        seam: &'static str,
    },
    RuntimeSeamInactive {
        seam: &'static str,
    },
    ProviderRouteMissing {
        requirement: ProviderRequirement,
    },
    CapabilitiesMissing {
        route: Option<RouteIdentity>,
        capabilities: Vec<CapabilityRequirement>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RejectionReason {
    ProviderRequirement {
        requirement: ProviderRequirement,
        route: Option<RouteIdentity>,
        missing_capabilities: Vec<CapabilityRequirement>,
    },
    ExternalConstraint {
        field: String,
        ceiling: ExternalCeiling,
        evidence_digest_sha256: String,
        detail_code: &'static str,
    },
    CrossFieldRule {
        detail_code: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EntryOutcome {
    Effective,
    Inactive { cause: InactiveCause },
    Unavailable,
    Unresolved { reason: UnresolvedReason },
    Rejected { reason: RejectionReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    Effective,
    Inactive,
    Unavailable,
    Unresolved,
    Rejected,
}

impl EntryOutcome {
    pub fn state(&self) -> EntryState {
        match self {
            Self::Effective => EntryState::Effective,
            Self::Inactive { .. } => EntryState::Inactive,
            Self::Unavailable => EntryState::Unavailable,
            Self::Unresolved { .. } => EntryState::Unresolved,
            Self::Rejected { .. } => EntryState::Rejected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedEntry {
    pub ordinal: u16,
    pub family_id: &'static str,
    pub semantic_key: &'static str,
    pub requested: Option<ResolutionValue>,
    pub effective: Option<ResolutionValue>,
    pub provenance: Option<ResolutionProvenance>,
    pub outcome: EntryOutcome,
    pub adjustments: Vec<Adjustment>,
    pub shadowed: Vec<ShadowedValue>,
    pub default: DefaultSpec,
    pub strategy_slots: &'static [CoreStrategySlot],
    pub optimization: OptimizationSpec,
    pub benchmark_relevance: BenchmarkRelevance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolutionReport {
    pub schema_version: u16,
    pub registry_id: &'static str,
    pub registry_revision: u16,
    pub registry_digest: &'static str,
    pub input_digest_sha256: String,
    pub effective_digest_sha256: String,
    pub resolution_digest_sha256: String,
    pub profile_digest_sha256: Option<String>,
    pub entries: Vec<ResolvedEntry>,
}

/// Atomic success wrapper. It is constructed only after every active family is effective; inactive
/// and unavailable families remain present in the 160-entry report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ResolvedTunableSet {
    pub(crate) report: ResolutionReport,
}

impl ResolvedTunableSet {
    pub fn report(&self) -> &ResolutionReport {
        &self.report
    }

    pub fn into_report(self) -> ResolutionReport {
        self.report
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FamilyFailure {
    pub family_id: &'static str,
    pub state: EntryState,
    pub reason_code: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    InvalidInput,
    ActiveResolutionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolutionFailureReport {
    pub schema_version: u16,
    pub code: FailureCode,
    pub detail: String,
    pub failures: Vec<FamilyFailure>,
    pub report: Option<ResolutionReport>,
}

impl std::fmt::Display for ResolutionFailureReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for ResolutionFailureReport {}
