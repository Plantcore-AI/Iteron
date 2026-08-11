use iteron_tunables::{ExternalCeiling, RuntimeResolutionError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FactLayer {
    Implementation,
    Default,
    Activation,
    Constraint {
        field: &'static str,
        ceiling: ExternalCeiling,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FactGapReason {
    RegistryUnavailable,
    RegistryUnavailableOwnerPresent,
    OwnerGetterMissing,
    OwnerSchemaMismatch,
    RequiredOwnerFieldUnknown,
    IndependentAuthorityMissing,
    ExternalCeilingBelowSchemaMinimum,
    GovernedCatalogMaterializerMissing,
    ExplicitlyDisabled,
}

impl FactGapReason {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::RegistryUnavailable => "registry_unavailable",
            Self::RegistryUnavailableOwnerPresent => "registry_unavailable_owner_present",
            Self::OwnerGetterMissing => "owner_getter_missing",
            Self::OwnerSchemaMismatch => "owner_schema_mismatch",
            Self::RequiredOwnerFieldUnknown => "required_owner_field_unknown",
            Self::IndependentAuthorityMissing => "independent_authority_missing",
            Self::ExternalCeilingBelowSchemaMinimum => "external_ceiling_below_schema_minimum",
            Self::GovernedCatalogMaterializerMissing => "governed_catalog_materializer_missing",
            Self::ExplicitlyDisabled => "explicitly_disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderProcessFactGap {
    pub ordinal: u16,
    pub family_id: &'static str,
    pub layer: FactLayer,
    pub reason: FactGapReason,
}

impl ProviderProcessFactGap {
    pub(super) const fn new(
        ordinal: u16,
        family_id: &'static str,
        layer: FactLayer,
        reason: FactGapReason,
    ) -> Self {
        Self {
            ordinal,
            family_id,
            layer,
            reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppliedConstraint {
    pub family_id: &'static str,
    pub field: &'static str,
    pub ceiling: ExternalCeiling,
}

/// Bounded by the static 47-family adapter inventory. Unknown owner state is retained as a gap,
/// never collapsed into an empty/default value.
#[derive(Debug, Default)]
pub(crate) struct ProviderProcessFactsReport {
    pub observed_defaults: Vec<&'static str>,
    pub declared_owner_values: Vec<&'static str>,
    pub active_families: Vec<&'static str>,
    pub inactive_families: Vec<&'static str>,
    pub unavailable_families: Vec<&'static str>,
    pub constraints: Vec<AppliedConstraint>,
    pub gaps: Vec<ProviderProcessFactGap>,
}

impl ProviderProcessFactsReport {
    pub(super) fn push_gap(&mut self, gap: ProviderProcessFactGap) {
        debug_assert!(
            self.gaps.len() < 192,
            "86..=132 gap inventory is fixed-bounded"
        );
        self.gaps.push(gap);
    }

    pub(super) fn constrained(
        &mut self,
        family_id: &'static str,
        field: &'static str,
        ceiling: ExternalCeiling,
    ) {
        self.constraints.push(AppliedConstraint {
            family_id,
            field,
            ceiling,
        });
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProviderProcessFactError {
    #[error("the selected provider is absent from the settled provider directory")]
    UnknownProvider,
    #[error("the supplied model capabilities do not match the selected directory route")]
    StaleModelCapabilities,
    #[error("the selected route attestation belongs to another provider/model")]
    RouteIdentityMismatch,
    #[error("the selected provider does not attest one configured request control")]
    ProviderControlMismatch,
    #[error("a configured fallback route is duplicated, malformed, or not admitted")]
    InvalidFallbackRoute,
    #[error("the route capability attestation no longer matches the executable owner surfaces")]
    StaleRouteCapabilities,
    #[error("the supplied run budget is invalid")]
    InvalidBudget,
    #[error("runtime owner value for `{0}` exceeds the registry integer representation")]
    IntegerOverflow(&'static str),
    #[error("the configured verification command is outside its bounded schema")]
    InvalidVerificationCommand,
    #[error("the typed verification owner policy is invalid or disagrees with its verifier floor")]
    InvalidVerificationPolicy,
    #[error("provider/process owner evidence could not be encoded")]
    EvidenceEncoding,
    #[error(transparent)]
    Resolution(#[from] RuntimeResolutionError),
}
