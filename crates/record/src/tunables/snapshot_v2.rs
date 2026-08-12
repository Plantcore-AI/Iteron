//! Reconstructable V2 tunables checkpoint projection and validation.

use super::{
    LEGACY_REGISTRY_ID, TunablesSnapshotError, digest_json, is_known_registry_id, is_sha256,
    safe_id,
};
use iteron_protocol::{
    MAX_RUN_GENESIS_TUNABLE_CEILINGS, MAX_RUN_GENESIS_TUNABLE_ENTRIES,
    MAX_RUN_GENESIS_TUNABLES_V2_BYTES, MAX_RUN_GENESIS_TUNABLES_V2_DEPTH,
    MAX_RUN_GENESIS_TUNABLES_V2_NODES, RUN_GENESIS_TUNABLES_V2_CANONICALIZATION,
    RunGenesisFixedAuthorityBindingV2, RunGenesisFixedAuthorityIdV2, RunGenesisTunableEntryV2,
    RunGenesisTunableState, RunGenesisTunablesSnapshotV2, RunGenesisTunablesVersionV2,
};
use iteron_tunables::{
    EntryOutcome, EntryState, FixedAuthorityAttestation, FixedAuthorityId, ResolutionReport,
    ResolutionSource, ResolutionValue, RuntimeBindingSpec, fixed_authority_value_digest_sha256,
};
use serde::Serialize;

const LEGACY_EFFECTIVE_CANONICALIZATION: &str = "core-tunables-effective-json-v1";
const EFFECTIVE_CANONICALIZATION: &str = "iteron-tunables-effective-json-v1";

fn protocol_fixed_authority(authority: FixedAuthorityId) -> RunGenesisFixedAuthorityIdV2 {
    match authority {
        FixedAuthorityId::StrategyInvariant => RunGenesisFixedAuthorityIdV2::StrategyInvariant,
        FixedAuthorityId::OperatorBoundary => RunGenesisFixedAuthorityIdV2::OperatorBoundary,
        FixedAuthorityId::GovernedArtifactBoundary => {
            RunGenesisFixedAuthorityIdV2::GovernedArtifactBoundary
        }
        FixedAuthorityId::RuntimeInvariant => RunGenesisFixedAuthorityIdV2::RuntimeInvariant,
        FixedAuthorityId::KernelInvariant => RunGenesisFixedAuthorityIdV2::KernelInvariant,
        FixedAuthorityId::ProviderDiscoveryBootstrap => {
            RunGenesisFixedAuthorityIdV2::ProviderDiscoveryBootstrap
        }
        FixedAuthorityId::OperatorPromptInput => RunGenesisFixedAuthorityIdV2::OperatorPromptInput,
        FixedAuthorityId::GovernedCatalogMaterialization => {
            RunGenesisFixedAuthorityIdV2::GovernedCatalogMaterialization
        }
        FixedAuthorityId::ChildOverlayMaterialization => {
            RunGenesisFixedAuthorityIdV2::ChildOverlayMaterialization
        }
        FixedAuthorityId::McpConfigurationMaterialization => {
            RunGenesisFixedAuthorityIdV2::McpConfigurationMaterialization
        }
    }
}

fn fixed_binding(attestation: &FixedAuthorityAttestation) -> RunGenesisFixedAuthorityBindingV2 {
    RunGenesisFixedAuthorityBindingV2 {
        authority: protocol_fixed_authority(attestation.authority),
        owner_value_digest_sha256: attestation.owner_value_digest_sha256.clone(),
    }
}

#[derive(Serialize)]
struct SnapshotPayloadV2<'a> {
    version: RunGenesisTunablesVersionV2,
    canonicalization: &'a str,
    resolution_schema_version: u16,
    registry_id: &'a str,
    registry_schema_version: u16,
    family_schema_version: u16,
    registry_revision: u16,
    registry_digest_sha256: &'a str,
    input_digest_sha256: &'a str,
    effective_digest_sha256: &'a str,
    resolution_digest_sha256: &'a str,
    profile_digest_sha256: &'a Option<String>,
    entries: &'a [RunGenesisTunableEntryV2],
}

#[derive(Serialize)]
struct EffectivePayloadV2<'a> {
    canonicalization: &'static str,
    registry_id: &'a str,
    registry_revision: u16,
    registry_digest: &'a str,
    entries: Vec<EffectiveEntryV2<'a>>,
}

#[derive(Serialize)]
struct EffectiveEntryV2<'a> {
    ordinal: u16,
    family_id: &'a str,
    state: RunGenesisTunableState,
    effective: Option<ResolutionValue>,
}

#[derive(Serialize)]
struct EffectiveReportEntry<'a> {
    ordinal: u16,
    family_id: &'static str,
    state: EntryState,
    effective: &'a Option<iteron_tunables::ResolutionValue>,
}

#[derive(Serialize)]
struct EffectiveReportPayload<'a> {
    canonicalization: &'static str,
    registry_id: &'a str,
    registry_revision: u16,
    registry_digest: &'a str,
    entries: Vec<EffectiveReportEntry<'a>>,
}

fn payload(snapshot: &RunGenesisTunablesSnapshotV2) -> SnapshotPayloadV2<'_> {
    SnapshotPayloadV2 {
        version: snapshot.version,
        canonicalization: &snapshot.canonicalization,
        resolution_schema_version: snapshot.resolution_schema_version,
        registry_id: &snapshot.registry_id,
        registry_schema_version: snapshot.registry_schema_version,
        family_schema_version: snapshot.family_schema_version,
        registry_revision: snapshot.registry_revision,
        registry_digest_sha256: &snapshot.registry_digest_sha256,
        input_digest_sha256: &snapshot.input_digest_sha256,
        effective_digest_sha256: &snapshot.effective_digest_sha256,
        resolution_digest_sha256: &snapshot.resolution_digest_sha256,
        profile_digest_sha256: &snapshot.profile_digest_sha256,
        entries: &snapshot.entries,
    }
}

#[derive(Default)]
struct JsonBudget {
    nodes: usize,
}

impl JsonBudget {
    fn observe(
        &mut self,
        value: &serde_json::Value,
        depth: usize,
    ) -> Result<(), TunablesSnapshotError> {
        self.observe_field(None, value, depth, false)
    }

    /// Both bounds are charged here rather than in [`Self::observe`], because the recursion below
    /// re-enters this function directly. Charged in the caller, `nodes` was incremented once per
    /// top-level projection instead of once per node, and the depth bound was never re-checked
    /// after the first level: a deep or wide nested projection passed validation unbounded.
    fn observe_field(
        &mut self,
        field: Option<&str>,
        value: &serde_json::Value,
        depth: usize,
        inherited_sha256_field: bool,
    ) -> Result<(), TunablesSnapshotError> {
        if depth > MAX_RUN_GENESIS_TUNABLES_V2_DEPTH {
            return invalid("a V2 projection exceeds its depth bound");
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(TunablesSnapshotError::Invalid {
                reason: "V2 projection node count overflow",
            })?;
        if self.nodes > MAX_RUN_GENESIS_TUNABLES_V2_NODES {
            return invalid("V2 projections exceed their node bound");
        }
        let sha256_field = inherited_sha256_field
            || field.is_some_and(|field| field == "sha256" || field.ends_with("_sha256"));
        match value {
            serde_json::Value::Null | serde_json::Value::Bool(_) => Ok(()),
            serde_json::Value::Number(number)
                if number.as_i64().is_some() || number.as_u64().is_some() =>
            {
                Ok(())
            }
            serde_json::Value::Number(_) => {
                invalid("V2 projections may not contain floating-point values")
            }
            serde_json::Value::String(value) if sha256_field && is_sha256(value) => Ok(()),
            // Resolver reports carry a closed `RouteIdentity` inside capability-inactive
            // explanations.  A content-addressed route revision is a machine identifier, not
            // interaction content; the ordinary free-text scrubber intentionally masks its
            // 64-hex suffix.  Admit it only at the typed route field and only through the same
            // bounded machine-id validator used by the checkpoint envelope. Credential-shaped
            // or unbounded values still fail this gate.
            serde_json::Value::String(value)
                if field == Some("route_revision") && safe_id(value) =>
            {
                Ok(())
            }
            serde_json::Value::String(value) => validate_projection_text(value),
            serde_json::Value::Array(values) => values.iter().try_for_each(|value| {
                self.observe_field(None, value, depth.saturating_add(1), sha256_field)
            }),
            serde_json::Value::Object(fields) => fields.iter().try_for_each(|(key, value)| {
                if !safe_id(key) {
                    return invalid("a V2 projection contains an invalid field identifier");
                }
                self.observe_field(Some(key), value, depth.saturating_add(1), sha256_field)
            }),
        }
    }
}

fn invalid<T>(reason: &'static str) -> Result<T, TunablesSnapshotError> {
    Err(TunablesSnapshotError::Invalid { reason })
}

fn validate_projection_text(value: &str) -> Result<(), TunablesSnapshotError> {
    if value.len() > iteron_tunables::RESOLUTION_INPUT_MAX_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        || crate::redact::scrub(value) != value
    {
        return invalid("a V2 projection contains unbounded, control, or credential-shaped text");
    }
    Ok(())
}

fn profile_matches(entry: &RunGenesisTunableEntryV2, profile_digest: &str) -> bool {
    entry
        .provenance
        .as_ref()
        .and_then(|value| value.get("source"))
        .is_some_and(|source| {
            source.get("type").and_then(serde_json::Value::as_str) == Some("profile")
                && source
                    .get("profile_digest_sha256")
                    .and_then(serde_json::Value::as_str)
                    == Some(profile_digest)
        })
}

fn recompute_effective_digest(
    snapshot: &RunGenesisTunablesSnapshotV2,
) -> Result<String, TunablesSnapshotError> {
    let entries = snapshot
        .entries
        .iter()
        .map(|entry| {
            let effective = entry
                .effective_value
                .clone()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| TunablesSnapshotError::Invalid {
                    reason: "a V2 effective value is not a canonical typed tunable value",
                })?;
            Ok(EffectiveEntryV2 {
                ordinal: entry.ordinal,
                family_id: &entry.family_id,
                state: entry.state,
                effective,
            })
        })
        .collect::<Result<Vec<_>, TunablesSnapshotError>>()?;
    let canonicalization = if snapshot.registry_id == LEGACY_REGISTRY_ID {
        LEGACY_EFFECTIVE_CANONICALIZATION
    } else {
        EFFECTIVE_CANONICALIZATION
    };
    digest_json(&EffectivePayloadV2 {
        canonicalization,
        registry_id: &snapshot.registry_id,
        registry_revision: snapshot.registry_revision,
        registry_digest: &snapshot.registry_digest_sha256,
        entries,
    })
}

pub(super) fn effective_digest_from_report(
    report: &ResolutionReport,
) -> Result<String, TunablesSnapshotError> {
    let entries = report
        .entries
        .iter()
        .map(|entry| EffectiveReportEntry {
            ordinal: entry.ordinal,
            family_id: entry.family_id,
            state: entry.outcome.state(),
            effective: &entry.effective,
        })
        .collect();
    digest_json(&EffectiveReportPayload {
        canonicalization: EFFECTIVE_CANONICALIZATION,
        registry_id: report.registry_id,
        registry_revision: report.registry_revision,
        registry_digest: report.registry_digest,
        entries,
    })
}

fn validated_report_fixed_attestations(
    report: &ResolutionReport,
) -> Result<std::collections::BTreeMap<&str, &FixedAuthorityAttestation>, TunablesSnapshotError> {
    if report.fixed_authority_attestations.len() > iteron_tunables::EXPECTED_FAMILY_COUNT {
        return invalid("resolver report fixed-authority inventory exceeds its family bound");
    }
    let mut attestations = std::collections::BTreeMap::new();
    for attestation in &report.fixed_authority_attestations {
        if !safe_id(&attestation.family_id)
            || !is_sha256(&attestation.owner_value_digest_sha256)
            || attestations
                .insert(attestation.family_id.as_str(), attestation)
                .is_some()
        {
            return invalid("resolver report has an invalid or duplicate fixed-authority binding");
        }
    }
    for (entry, family) in report.entries.iter().zip(iteron_tunables::families()) {
        let observed = attestations.get(family.id).copied();
        match (family.runtime_binding, entry.outcome.state()) {
            (RuntimeBindingSpec::Fixed { authority, .. }, EntryState::Effective) => {
                let Some(attestation) = observed else {
                    return invalid("an effective fixed report entry lacks its authority binding");
                };
                let Some(value) = entry.effective.as_ref() else {
                    return invalid("an effective fixed report entry lacks its value");
                };
                let expected = fixed_authority_value_digest_sha256(family.id, authority, value)
                    .map_err(|_| TunablesSnapshotError::Invalid {
                        reason: "a report fixed-authority digest could not be recomputed",
                    })?;
                if attestation.authority != authority
                    || attestation.owner_value_digest_sha256 != expected
                {
                    return invalid("a report fixed-authority binding disagrees with its value");
                }
            }
            (RuntimeBindingSpec::Fixed { .. }, _) => {
                if observed.is_some() {
                    return invalid(
                        "a non-effective fixed report entry carries an authority binding",
                    );
                }
            }
            (RuntimeBindingSpec::Effective { .. }, _) => {
                if observed.is_some() {
                    return invalid("a Full report entry carries a fixed-authority binding");
                }
            }
            (RuntimeBindingSpec::Unbound { .. }, _) => {
                return invalid("a report entry uses unbound runtime metadata");
            }
        }
    }
    if attestations.len()
        != report
            .entries
            .iter()
            .zip(iteron_tunables::families())
            .filter(|(entry, family)| {
                entry.outcome.state() == EntryState::Effective
                    && matches!(family.runtime_binding, RuntimeBindingSpec::Fixed { .. })
            })
            .count()
    {
        return invalid("resolver report fixed-authority bindings are not bijective");
    }
    Ok(attestations)
}

/// Validate all V2 bounds and independently recompute both effective and checkpoint commitments.
pub fn validate_tunables_snapshot_v2(
    snapshot: &RunGenesisTunablesSnapshotV2,
) -> Result<(), TunablesSnapshotError> {
    if snapshot.version != RunGenesisTunablesVersionV2::V2
        || snapshot.canonicalization != RUN_GENESIS_TUNABLES_V2_CANONICALIZATION
    {
        return invalid("unsupported V2 snapshot version or canonicalization");
    }
    if snapshot.resolution_schema_version == 0
        || snapshot.registry_schema_version == 0
        || snapshot.family_schema_version == 0
        || snapshot.registry_revision == 0
        || !is_known_registry_id(&snapshot.registry_id)
    {
        return invalid("V2 registry identity or schema version is invalid");
    }
    for digest in [
        &snapshot.registry_digest_sha256,
        &snapshot.input_digest_sha256,
        &snapshot.effective_digest_sha256,
        &snapshot.resolution_digest_sha256,
        &snapshot.snapshot_digest_sha256,
    ] {
        if !is_sha256(digest) {
            return invalid("a required V2 digest is not lowercase SHA-256");
        }
    }
    if snapshot
        .profile_digest_sha256
        .as_deref()
        .is_some_and(|digest| !is_sha256(digest))
    {
        return invalid("the V2 profile digest is not lowercase SHA-256");
    }
    if snapshot.entries.len() != MAX_RUN_GENESIS_TUNABLE_ENTRIES {
        return invalid("V2 snapshot does not contain exactly 160 families");
    }

    let mut families = std::collections::BTreeSet::new();
    let mut semantic_keys = std::collections::BTreeSet::new();
    let mut budget = JsonBudget::default();
    for (index, entry) in snapshot.entries.iter().enumerate() {
        let ordinal = u16::try_from(index + 1).map_err(|_| TunablesSnapshotError::Invalid {
            reason: "V2 snapshot ordinal overflow",
        })?;
        if entry.ordinal != ordinal
            || !safe_id(&entry.family_id)
            || !safe_id(&entry.semantic_key)
            || !families.insert(&entry.family_id)
            || !semantic_keys.insert(&entry.semantic_key)
        {
            return invalid("V2 entry identity, order, or uniqueness is invalid");
        }
        let Some(family) = iteron_tunables::families().get(index) else {
            return invalid("V2 entry has no canonical family binding");
        };
        if entry.ordinal != family.ordinal
            || entry.family_id != family.id
            || entry.semantic_key != family.semantic_key
        {
            return invalid("V2 entry identity disagrees with the canonical registry");
        }
        let effective = entry.effective_value.is_some();
        let inactive = entry.inactive_reason.is_some();
        if effective != (entry.state == RunGenesisTunableState::Effective)
            || inactive != (entry.state == RunGenesisTunableState::Inactive)
            || (effective && entry.provenance.is_none())
            || entry.ceiling_adjustments.len() > MAX_RUN_GENESIS_TUNABLE_CEILINGS
        {
            return invalid("V2 entry state and explanation fields are inconsistent");
        }
        match (family.runtime_binding, entry.state) {
            (RuntimeBindingSpec::Fixed { authority, .. }, RunGenesisTunableState::Effective) => {
                let Some(binding) = entry.fixed_authority_binding.as_ref() else {
                    return invalid("an effective fixed V2 entry lacks its authority binding");
                };
                if binding.authority != protocol_fixed_authority(authority)
                    || !is_sha256(&binding.owner_value_digest_sha256)
                {
                    return invalid("a V2 fixed-authority identity is invalid");
                }
                let value = entry
                    .effective_value
                    .clone()
                    .map(serde_json::from_value::<ResolutionValue>)
                    .transpose()
                    .map_err(|_| TunablesSnapshotError::Invalid {
                        reason: "a V2 fixed-authority value is not canonical",
                    })?
                    .ok_or(TunablesSnapshotError::Invalid {
                        reason: "an effective fixed V2 entry has no value",
                    })?;
                let expected = fixed_authority_value_digest_sha256(family.id, authority, &value)
                    .map_err(|_| TunablesSnapshotError::Invalid {
                        reason: "a V2 fixed-authority digest could not be recomputed",
                    })?;
                if binding.owner_value_digest_sha256 != expected {
                    return invalid("a V2 fixed-authority digest disagrees with its value");
                }
            }
            (RuntimeBindingSpec::Fixed { .. }, _) => {
                if entry.fixed_authority_binding.is_some() {
                    return invalid("an inactive fixed V2 entry carries an authority binding");
                }
            }
            (RuntimeBindingSpec::Effective { .. }, _) => {
                if entry.fixed_authority_binding.is_some() {
                    return invalid("a Full V2 entry carries a fixed-authority binding");
                }
            }
            (RuntimeBindingSpec::Unbound { .. }, _) => {
                return invalid("a V2 entry uses unbound runtime metadata");
            }
        }
        if entry.profile_applied {
            let Some(profile_digest) = snapshot.profile_digest_sha256.as_deref() else {
                return invalid("a V2 entry claims a profile but the snapshot has none");
            };
            if !profile_matches(entry, profile_digest) {
                return invalid("a V2 entry profile projection disagrees with provenance");
            }
        }
        for value in entry
            .effective_value
            .iter()
            .chain(entry.provenance.iter())
            .chain(entry.ceiling_adjustments.iter())
            .chain(entry.inactive_reason.iter())
        {
            budget.observe(value, 0)?;
        }
    }
    let payload_bytes = serde_json::to_vec(&payload(snapshot))
        .map_err(|_| TunablesSnapshotError::Invalid {
            reason: "V2 canonical snapshot encoding failed",
        })?
        .len();
    if payload_bytes > MAX_RUN_GENESIS_TUNABLES_V2_BYTES {
        return invalid("V2 snapshot exceeds its canonical byte bound");
    }
    if recompute_effective_digest(snapshot)? != snapshot.effective_digest_sha256 {
        return invalid("V2 effective values do not match the effective digest");
    }
    if digest_json(&payload(snapshot))? != snapshot.snapshot_digest_sha256 {
        return invalid("V2 snapshot self-digest mismatch");
    }
    Ok(())
}

/// Project the accepted resolver report into a complete immutable V2 checkpoint.
pub(super) fn snapshot_v2_from_report(
    report: &ResolutionReport,
) -> Result<RunGenesisTunablesSnapshotV2, TunablesSnapshotError> {
    if effective_digest_from_report(report)? != report.effective_digest_sha256 {
        return invalid("resolver report effective digest does not match its effective values");
    }
    let fixed_attestations = validated_report_fixed_attestations(report)?;
    let entries = report
        .entries
        .iter()
        .map(|entry| {
            let state = match entry.outcome.state() {
                EntryState::Effective => RunGenesisTunableState::Effective,
                EntryState::Inactive => RunGenesisTunableState::Inactive,
                EntryState::Unavailable => RunGenesisTunableState::Unavailable,
                EntryState::Unresolved | EntryState::Rejected => {
                    return invalid("atomic resolver success contains a failed active V2 family");
                }
            };
            let effective_value = entry
                .effective
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| TunablesSnapshotError::Invalid {
                    reason: "effective tunable value encoding failed",
                })?;
            let provenance = entry
                .provenance
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| TunablesSnapshotError::Invalid {
                    reason: "tunable provenance encoding failed",
                })?;
            let profile_applied = entry.provenance.as_ref().is_some_and(|provenance| {
                matches!(provenance.source, ResolutionSource::Profile { .. })
            });
            let ceiling_adjustments = entry
                .adjustments
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| TunablesSnapshotError::Invalid {
                    reason: "tunable ceiling encoding failed",
                })?;
            let inactive_reason = match &entry.outcome {
                EntryOutcome::Inactive { cause } => {
                    Some(serde_json::to_value(cause).map_err(|_| {
                        TunablesSnapshotError::Invalid {
                            reason: "tunable inactive reason encoding failed",
                        }
                    })?)
                }
                _ => None,
            };
            let fixed_authority_binding = fixed_attestations
                .get(entry.family_id)
                .map(|attestation| fixed_binding(attestation));
            Ok(RunGenesisTunableEntryV2 {
                ordinal: entry.ordinal,
                family_id: entry.family_id.to_owned(),
                semantic_key: entry.semantic_key.to_owned(),
                state,
                effective_value,
                provenance,
                profile_applied,
                ceiling_adjustments,
                inactive_reason,
                fixed_authority_binding,
            })
        })
        .collect::<Result<Vec<_>, TunablesSnapshotError>>()?;
    let mut snapshot = RunGenesisTunablesSnapshotV2 {
        version: RunGenesisTunablesVersionV2::V2,
        canonicalization: RUN_GENESIS_TUNABLES_V2_CANONICALIZATION.to_owned(),
        resolution_schema_version: report.schema_version,
        registry_id: report.registry_id.to_owned(),
        registry_schema_version: iteron_tunables::REGISTRY_SCHEMA_VERSION,
        family_schema_version: iteron_tunables::FAMILY_SCHEMA_VERSION,
        registry_revision: report.registry_revision,
        registry_digest_sha256: report.registry_digest.to_owned(),
        input_digest_sha256: report.input_digest_sha256.clone(),
        effective_digest_sha256: report.effective_digest_sha256.clone(),
        resolution_digest_sha256: report.resolution_digest_sha256.clone(),
        profile_digest_sha256: report.profile_digest_sha256.clone(),
        entries,
        snapshot_digest_sha256: String::new(),
    };
    snapshot.snapshot_digest_sha256 = digest_json(&payload(&snapshot))?;
    validate_tunables_snapshot_v2(&snapshot)?;
    Ok(snapshot)
}
