//! Version-neutral runtime projection of one immutable tunables truth.

use iteron_protocol::{
    RunGenesisFixedAuthorityBindingV2, RunGenesisFixedAuthorityIdV2, RunGenesisTunableState,
};
use iteron_record::TunablesCheckpoint;
use iteron_tunables::{
    EvidenceProjectionId, FixedAuthorityId, ResolutionValue, RuntimeBindingSpec, RuntimeGetterId,
    RuntimeOwnerReceipt, fixed_authority_value_digest_sha256,
};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use super::fixed_artifacts::provider_discovery_owner_value;
use super::fixed_artifacts::{
    FixedArtifactReceipts, FixedAuthorityReceipts, checkpoint_fixed_consumer,
    configured_absence_reason, requires_live_authority_resample, requires_live_receipt,
};

#[derive(Debug, Clone)]
struct SnapshotEntryState {
    state: RunGenesisTunableState,
    provenance: Option<serde_json::Value>,
    inactive_reason: Option<serde_json::Value>,
    fixed_authority_binding: Option<RunGenesisFixedAuthorityBindingV2>,
}

#[derive(Debug, Clone)]
pub(crate) struct EffectiveTunablesView {
    effective_digest_sha256: String,
    values: BTreeMap<String, ResolutionValue>,
    entry_states: BTreeMap<String, SnapshotEntryState>,
    snapshot_families: BTreeSet<String>,
    provenance_families: BTreeSet<String>,
    snapshot_digest_sha256: Option<String>,
    active_getter: Cell<Option<RuntimeGetterId>>,
    consumed: RefCell<BTreeSet<String>>,
    fixed_consumed: RefCell<BTreeSet<String>>,
    binding_error: RefCell<Option<EffectiveViewError>>,
    enforce_bindings: bool,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(crate) enum EffectiveViewError {
    #[error("historical V1 tunables checkpoints contain identity only and cannot drive runtime")]
    HistoricalIdentityOnly,
    #[error("effective tunables contain a duplicate family `{0}`")]
    DuplicateFamily(String),
    #[error("effective tunable `{0}` is absent or inactive")]
    NotEffective(String),
    #[error("effective tunable `{family}` has the wrong type; expected {expected}")]
    WrongType {
        family: String,
        expected: &'static str,
    },
    #[error("effective tunable `{0}` could not be decoded from its immutable checkpoint")]
    Decode(String),
    #[error("immutable tunables checkpoint has no recognized named runtime profile")]
    UnknownProfile,
    #[error("immutable tunables checkpoint does not match the exact running registry identity")]
    RegistryIdentityMismatch,
    #[error("effective tunable `{0}` has no canonical owner provenance")]
    ProvenanceMismatch(String),
    #[error("effective tunable `{family}` was read outside its registered getter `{expected:?}`")]
    GetterUnbound {
        family: String,
        expected: RuntimeGetterId,
    },
    #[error(
        "effective tunable `{family}` was read by `{observed:?}`; registered getter is `{expected:?}`"
    )]
    GetterMismatch {
        family: String,
        expected: RuntimeGetterId,
        observed: RuntimeGetterId,
    },
    #[error("runtime binding receipt is missing effective family `{0}`")]
    MissingGetterReceipt(String),
    #[error("runtime binding receipt has no validated V2 evidence projection")]
    MissingEvidenceProjection,
    #[error("runtime binding receipt has no production-owner observation for `{0}`")]
    MissingOwnerReceipt(String),
    #[error("runtime binding metadata disagrees with implementation status for `{0}`")]
    InvalidBindingMetadata(String),
    #[error("fixed authority evidence for `{0}` does not have its registered runtime shape")]
    InvalidFixedAuthorityEvidence(String),
    #[error("fixed artifact `{0}` is effective but has no exact live materializer receipt")]
    MissingFixedArtifactReceipt(String),
    #[error("fixed artifact `{0}` does not match the exact live materializer identity")]
    FixedArtifactMismatch(String),
    #[error("fixed authority `{0}` has no sealed live owner receipt on resume")]
    MissingFixedAuthorityRuntimeReceipt(String),
    #[error("fixed authority `{0}` does not match the re-sampled live owner")]
    FixedAuthorityRuntimeMismatch(String),
    #[error("checkpoint-derived fixed family `{0}` was not read by its registered decoder")]
    MissingFixedConsumerReceipt(String),
    #[error(
        "checkpoint-derived fixed family `{family}` was read by `{observed:?}`; registered decoder is `{expected:?}`"
    )]
    FixedConsumerMismatch {
        family: String,
        expected: RuntimeGetterId,
        observed: RuntimeGetterId,
    },
    #[error("checkpoint-derived fixed family `{family}` was read outside `{expected:?}`")]
    FixedConsumerUnbound {
        family: String,
        expected: RuntimeGetterId,
    },
    #[error("fixed authority `{0}` has an invalid durable inactive state")]
    InvalidFixedAuthorityState(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeBindingReceipt {
    pub snapshot_digest_sha256: String,
    pub effective_digest_sha256: String,
    pub effective_family_count: usize,
    pub getter_count: usize,
    pub fixed_family_count: usize,
    pub fixed_consumer_count: usize,
}

impl EffectiveTunablesView {
    #[cfg(test)]
    pub(crate) fn from_test_values(values: BTreeMap<String, ResolutionValue>) -> Self {
        Self {
            effective_digest_sha256: "0".repeat(64),
            values,
            entry_states: BTreeMap::new(),
            snapshot_families: BTreeSet::new(),
            provenance_families: BTreeSet::new(),
            snapshot_digest_sha256: None,
            active_getter: Cell::new(None),
            consumed: RefCell::new(BTreeSet::new()),
            fixed_consumed: RefCell::new(BTreeSet::new()),
            binding_error: RefCell::new(None),
            enforce_bindings: false,
        }
    }

    pub(crate) fn from_checkpoint(
        checkpoint: &TunablesCheckpoint,
    ) -> Result<Self, EffectiveViewError> {
        let TunablesCheckpoint::V2(snapshot) = checkpoint else {
            return Err(EffectiveViewError::HistoricalIdentityOnly);
        };
        iteron_record::validate_tunables_snapshot_v2(snapshot)
            .map_err(|_| EffectiveViewError::Decode("checkpoint".into()))?;
        if snapshot.resolution_schema_version != iteron_tunables::RESOLUTION_SCHEMA_VERSION
            || snapshot.registry_id != iteron_tunables::REGISTRY_ID
            || snapshot.registry_schema_version != iteron_tunables::REGISTRY_SCHEMA_VERSION
            || snapshot.family_schema_version != iteron_tunables::FAMILY_SCHEMA_VERSION
            || snapshot.registry_revision != iteron_tunables::REGISTRY_REVISION
            || snapshot.registry_digest_sha256 != iteron_tunables::REGISTRY_DIGEST_SHA256
            || snapshot
                .entries
                .iter()
                .zip(iteron_tunables::families())
                .any(|(entry, family)| {
                    entry.ordinal != family.ordinal
                        || entry.family_id != family.id
                        || entry.semantic_key != family.semantic_key
                })
        {
            return Err(EffectiveViewError::RegistryIdentityMismatch);
        }
        let mut values = BTreeMap::new();
        let mut entry_states = BTreeMap::new();
        for entry in &snapshot.entries {
            if entry_states
                .insert(
                    entry.family_id.clone(),
                    SnapshotEntryState {
                        state: entry.state,
                        provenance: entry.provenance.clone(),
                        inactive_reason: entry.inactive_reason.clone(),
                        fixed_authority_binding: entry.fixed_authority_binding.clone(),
                    },
                )
                .is_some()
            {
                return Err(EffectiveViewError::DuplicateFamily(entry.family_id.clone()));
            }
            let Some(encoded) = &entry.effective_value else {
                continue;
            };
            let value = serde_json::from_value(encoded.clone())
                .map_err(|_| EffectiveViewError::Decode(entry.family_id.clone()))?;
            if values.insert(entry.family_id.clone(), value).is_some() {
                return Err(EffectiveViewError::DuplicateFamily(entry.family_id.clone()));
            }
        }
        Ok(Self {
            effective_digest_sha256: snapshot.effective_digest_sha256.clone(),
            values,
            entry_states,
            snapshot_families: snapshot
                .entries
                .iter()
                .map(|entry| entry.family_id.clone())
                .collect(),
            provenance_families: snapshot
                .entries
                .iter()
                .filter(|entry| entry.provenance.is_some())
                .map(|entry| entry.family_id.clone())
                .collect(),
            snapshot_digest_sha256: Some(snapshot.snapshot_digest_sha256.clone()),
            active_getter: Cell::new(None),
            consumed: RefCell::new(BTreeSet::new()),
            fixed_consumed: RefCell::new(BTreeSet::new()),
            binding_error: RefCell::new(None),
            enforce_bindings: true,
        })
    }

    pub(crate) fn with_getter<T>(&self, getter: RuntimeGetterId, read: impl FnOnce() -> T) -> T {
        let previous = self.active_getter.replace(Some(getter));
        let result = read();
        self.active_getter.set(previous);
        result
    }

    pub(crate) fn seal_runtime_binding_receipt(
        &self,
        owner_receipt: Option<&RuntimeOwnerReceipt>,
        fixed_artifacts: &FixedArtifactReceipts,
        fixed_authorities: &FixedAuthorityReceipts,
    ) -> Result<RuntimeBindingReceipt, EffectiveViewError> {
        if let Some(error) = self.binding_error.borrow().clone() {
            return Err(error);
        }
        let snapshot_digest_sha256 = self
            .snapshot_digest_sha256
            .clone()
            .ok_or(EffectiveViewError::MissingEvidenceProjection)?;
        let consumed = self.consumed.borrow();
        let fixed_consumed = self.fixed_consumed.borrow();
        let mut effective_family_count = 0usize;
        let mut fixed_family_count = 0usize;
        for family in iteron_tunables::families() {
            if !self.snapshot_families.contains(family.id) {
                return Err(EffectiveViewError::InvalidBindingMetadata(
                    family.id.to_owned(),
                ));
            }
            match family.runtime_binding {
                RuntimeBindingSpec::Effective { adapter, owner, .. }
                    if self.values.contains_key(family.id) =>
                {
                    effective_family_count += 1;
                    if !self.provenance_families.contains(family.id) {
                        return Err(EffectiveViewError::MissingOwnerReceipt(
                            family.id.to_owned(),
                        ));
                    }
                    if !self.entry_states.get(family.id).is_some_and(|entry| {
                        entry
                            .provenance
                            .as_ref()
                            .is_some_and(|value| canonical_provenance_matches(family, value))
                    }) {
                        return Err(EffectiveViewError::ProvenanceMismatch(family.id.to_owned()));
                    }
                    if owner_receipt
                        .is_some_and(|receipt| !receipt.contains(family.id, adapter, owner))
                    {
                        return Err(EffectiveViewError::MissingOwnerReceipt(
                            family.id.to_owned(),
                        ));
                    }
                    if !consumed.contains(family.id) {
                        return Err(EffectiveViewError::MissingGetterReceipt(
                            family.id.to_owned(),
                        ));
                    }
                }
                RuntimeBindingSpec::Fixed {
                    adapter, authority, ..
                } if self.values.contains_key(family.id) => {
                    fixed_family_count += 1;
                    if !self.provenance_families.contains(family.id) {
                        return Err(EffectiveViewError::MissingOwnerReceipt(
                            family.id.to_owned(),
                        ));
                    }
                    if !self.entry_states.get(family.id).is_some_and(|entry| {
                        entry
                            .provenance
                            .as_ref()
                            .is_some_and(|value| canonical_provenance_matches(family, value))
                    }) {
                        return Err(EffectiveViewError::ProvenanceMismatch(family.id.to_owned()));
                    }
                    let expected = self
                        .values
                        .get(family.id)
                        .expect("effective fixed value presence was checked");
                    let binding = validate_fixed_authority_binding(
                        family.id,
                        authority,
                        expected,
                        self.entry_states
                            .get(family.id)
                            .and_then(|entry| entry.fixed_authority_binding.as_ref()),
                    )?;
                    if owner_receipt.is_some_and(|receipt| {
                        !receipt.contains_fixed(
                            family.id,
                            adapter,
                            authority,
                            &binding.owner_value_digest_sha256,
                        )
                    }) {
                        return Err(EffectiveViewError::MissingOwnerReceipt(
                            family.id.to_owned(),
                        ));
                    }
                    if owner_receipt.is_none() && requires_live_authority_resample(family.id) {
                        if !fixed_authorities.contains(family.id) {
                            return Err(EffectiveViewError::MissingFixedAuthorityRuntimeReceipt(
                                family.id.to_owned(),
                            ));
                        }
                        if !fixed_authorities.matches(family.id, expected) {
                            return Err(EffectiveViewError::FixedAuthorityRuntimeMismatch(
                                family.id.to_owned(),
                            ));
                        }
                    }
                    if checkpoint_fixed_consumer(family.id).is_some()
                        && !fixed_consumed.contains(family.id)
                    {
                        return Err(EffectiveViewError::MissingFixedConsumerReceipt(
                            family.id.to_owned(),
                        ));
                    }
                    if requires_live_receipt(family.id) {
                        let expected = self
                            .values
                            .get(family.id)
                            .expect("effective fixed value presence was checked");
                        if !fixed_artifacts.contains(family.id) {
                            return Err(EffectiveViewError::MissingFixedArtifactReceipt(
                                family.id.to_owned(),
                            ));
                        }
                        if !fixed_artifacts.matches(family.id, expected) {
                            return Err(EffectiveViewError::FixedArtifactMismatch(
                                family.id.to_owned(),
                            ));
                        }
                    }
                }
                RuntimeBindingSpec::Fixed { .. } => {
                    validate_inactive_fixed_authority(family.id, &self.entry_states)?;
                }
                RuntimeBindingSpec::Effective { .. } => {}
                RuntimeBindingSpec::Unbound { .. } => {
                    return Err(EffectiveViewError::InvalidBindingMetadata(
                        family.id.to_owned(),
                    ));
                }
            }
            if family.runtime_binding.evidence() != Some(EvidenceProjectionId::RunGenesisTunablesV2)
            {
                return Err(EffectiveViewError::InvalidBindingMetadata(
                    family.id.to_owned(),
                ));
            }
        }
        Ok(RuntimeBindingReceipt {
            snapshot_digest_sha256,
            effective_digest_sha256: self.effective_digest_sha256.clone(),
            effective_family_count,
            getter_count: consumed.len(),
            fixed_family_count,
            fixed_consumer_count: fixed_consumed.len(),
        })
    }

    fn record_getter(&self, family_id: &str) -> Result<(), EffectiveViewError> {
        if !self.enforce_bindings {
            return Ok(());
        }
        let family = iteron_tunables::families()
            .iter()
            .find(|family| family.id == family_id || family.aliases.contains(&family_id))
            .ok_or_else(|| EffectiveViewError::NotEffective(family_id.to_owned()))?;
        let getter = match family.runtime_binding {
            RuntimeBindingSpec::Effective { getter, .. } => getter,
            RuntimeBindingSpec::Fixed { .. } => {
                let Some(expected) = checkpoint_fixed_consumer(family.id) else {
                    return Ok(());
                };
                return match self.active_getter.get() {
                    Some(observed) if observed == expected => {
                        self.fixed_consumed
                            .borrow_mut()
                            .insert(family.id.to_owned());
                        Ok(())
                    }
                    Some(observed) => Err(EffectiveViewError::FixedConsumerMismatch {
                        family: family.id.to_owned(),
                        expected,
                        observed,
                    }),
                    None => Err(EffectiveViewError::FixedConsumerUnbound {
                        family: family.id.to_owned(),
                        expected,
                    }),
                };
            }
            RuntimeBindingSpec::Unbound { .. } => return Ok(()),
        };
        match self.active_getter.get() {
            Some(observed) if observed == getter => {
                self.consumed.borrow_mut().insert(family.id.to_owned());
                Ok(())
            }
            Some(observed) => Err(EffectiveViewError::GetterMismatch {
                family: family.id.to_owned(),
                expected: getter,
                observed,
            }),
            None => Err(EffectiveViewError::GetterUnbound {
                family: family.id.to_owned(),
                expected: getter,
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn remove_getter_receipt(&self, family: &str) {
        self.consumed.borrow_mut().remove(family);
    }

    #[cfg(test)]
    pub(crate) fn remove_fixed_consumer_receipt(&self, family: &str) {
        self.fixed_consumed.borrow_mut().remove(family);
    }

    pub(crate) fn runtime_profile(
        &self,
    ) -> Result<iteron_tunables::RuntimeProfile, EffectiveViewError> {
        runtime_profile_from_isolation_label(self.enumeration("session_isolation_profile")?)
            .ok_or(EffectiveViewError::UnknownProfile)
    }

    pub(crate) fn value(&self, family: &str) -> Result<&ResolutionValue, EffectiveViewError> {
        self.record_getter(family)?;
        self.values
            .get(family)
            .ok_or_else(|| EffectiveViewError::NotEffective(family.to_owned()))
    }

    pub(crate) fn optional_value(&self, family: &str) -> Option<&ResolutionValue> {
        if self.values.contains_key(family)
            && let Err(error) = self.record_getter(family)
        {
            let mut slot = self.binding_error.borrow_mut();
            if slot.is_none() {
                *slot = Some(error);
            }
        }
        self.values.get(family)
    }

    pub(crate) fn boolean(&self, family: &str) -> Result<bool, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Boolean { value } => Ok(*value),
            _ => Err(wrong_type(family, "boolean")),
        }
    }

    pub(crate) fn integer(&self, family: &str) -> Result<i64, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Integer { value } => Ok(*value),
            _ => Err(wrong_type(family, "integer")),
        }
    }

    pub(crate) fn text(&self, family: &str) -> Result<&str, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Text { value } => Ok(value),
            _ => Err(wrong_type(family, "text")),
        }
    }

    pub(crate) fn enumeration(&self, family: &str) -> Result<&str, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Enum { value } => Ok(value),
            _ => Err(wrong_type(family, "enum")),
        }
    }

    pub(crate) fn object(
        &self,
        family: &str,
    ) -> Result<&BTreeMap<String, ResolutionValue>, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Object { fields } => Ok(fields),
            _ => Err(wrong_type(family, "object")),
        }
    }

    pub(crate) fn map(
        &self,
        family: &str,
    ) -> Result<&BTreeMap<String, ResolutionValue>, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Map { entries } => Ok(entries),
            _ => Err(wrong_type(family, "map")),
        }
    }
}

/// Recover the physical runtime-profile identity from the immutable family that owns session
/// isolation. The profile document digest is deliberately not consulted here: it fingerprints the
/// complete value-bearing document and therefore changes whenever a valid override is added.
pub(crate) fn checkpoint_runtime_profile(
    checkpoint: &TunablesCheckpoint,
) -> Option<iteron_tunables::RuntimeProfile> {
    let view = EffectiveTunablesView::from_checkpoint(checkpoint).ok()?;
    let ResolutionValue::Enum { value } = view.values.get("session_isolation_profile")? else {
        return None;
    };
    runtime_profile_from_isolation_label(value)
}

fn runtime_profile_from_isolation_label(label: &str) -> Option<iteron_tunables::RuntimeProfile> {
    match label {
        "interactive" => Some(iteron_tunables::RuntimeProfile::Interactive),
        "hermetic" => Some(iteron_tunables::RuntimeProfile::Benchmark),
        "durable" => Some(iteron_tunables::RuntimeProfile::Research),
        _ => None,
    }
}

fn wrong_type(family: &str, expected: &'static str) -> EffectiveViewError {
    EffectiveViewError::WrongType {
        family: family.to_owned(),
        expected,
    }
}

fn validate_inactive_fixed_authority(
    family: &str,
    states: &BTreeMap<String, SnapshotEntryState>,
) -> Result<(), EffectiveViewError> {
    let Some(entry) = states.get(family) else {
        return Err(EffectiveViewError::InvalidFixedAuthorityState(
            family.to_owned(),
        ));
    };
    if entry.state != RunGenesisTunableState::Inactive
        || entry.provenance.is_some()
        || entry.inactive_reason.is_none()
        || (requires_live_receipt(family)
            && !entry
                .inactive_reason
                .as_ref()
                .is_some_and(configured_absence_reason))
    {
        return Err(EffectiveViewError::InvalidFixedAuthorityState(
            family.to_owned(),
        ));
    }
    Ok(())
}

fn canonical_provenance_matches(
    family: &iteron_tunables::Family,
    provenance: &serde_json::Value,
) -> bool {
    let Some(source) = provenance.get("source") else {
        return false;
    };
    match source.get("type").and_then(serde_json::Value::as_str) {
        Some("declared" | "profile") => family.source.bindings.iter().any(|binding| {
            let kind = serde_json::to_value(binding.kind).ok();
            let trust = serde_json::to_value(binding.trust).ok();
            source.get("kind") == kind.as_ref()
                && source.get("trust") == trust.as_ref()
                && source
                    .get("declared_locator")
                    .and_then(serde_json::Value::as_str)
                    == Some(binding.locator)
        }),
        Some("default") => {
            let resolver_id = default_resolver_id(family.default.resolver);
            source
                .get("resolver_id")
                .and_then(serde_json::Value::as_str)
                == Some(resolver_id.as_str())
        }
        _ => false,
    }
}

fn default_resolver_id(resolver: iteron_tunables::DefaultResolver) -> String {
    match resolver {
        iteron_tunables::DefaultResolver::Literal => {
            "iteron://tunables/resolvers/literal-v1".into()
        }
        iteron_tunables::DefaultResolver::Builtin { resolver_id } => resolver_id.into(),
        iteron_tunables::DefaultResolver::ModelMetadata { field } => {
            format!("iteron://tunables/resolvers/model-metadata/{field}-v1")
        }
        iteron_tunables::DefaultResolver::ProviderCapability { capability } => {
            format!("iteron://tunables/resolvers/provider-capability/{capability}-v1")
        }
        iteron_tunables::DefaultResolver::Transport { field } => {
            format!("iteron://tunables/resolvers/transport/{field}-v1")
        }
        iteron_tunables::DefaultResolver::RuntimeObservation { field } => {
            format!("iteron://tunables/resolvers/runtime-observation/{field}-v1")
        }
        iteron_tunables::DefaultResolver::GovernedCatalog { catalog_id } => catalog_id.into(),
        iteron_tunables::DefaultResolver::Operator { input_id } => input_id.into(),
    }
}

fn validate_fixed_authority_binding<'a>(
    family: &str,
    authority: FixedAuthorityId,
    value: &ResolutionValue,
    binding: Option<&'a RunGenesisFixedAuthorityBindingV2>,
) -> Result<&'a RunGenesisFixedAuthorityBindingV2, EffectiveViewError> {
    let Some(binding) = binding else {
        return Err(EffectiveViewError::InvalidFixedAuthorityEvidence(
            family.to_owned(),
        ));
    };
    let authority_matches = binding.authority == protocol_fixed_authority(authority);
    let digest_matches = fixed_authority_value_digest_sha256(family, authority, value)
        .is_ok_and(|expected| expected == binding.owner_value_digest_sha256);
    if !authority_matches || !digest_matches {
        return Err(EffectiveViewError::InvalidFixedAuthorityEvidence(
            family.to_owned(),
        ));
    }
    Ok(binding)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{RunGenesisTunablesSnapshot, RunGenesisTunablesVersion};
    use iteron_tunables::{ProfileValue, RuntimeProfile, SourceKind};

    #[test]
    fn v1_identity_is_never_misrepresented_as_runtime_values() {
        let checkpoint = TunablesCheckpoint::V1(RunGenesisTunablesSnapshot {
            version: RunGenesisTunablesVersion::V1,
            canonicalization: "fixture".into(),
            resolution_schema_version: 1,
            registry_id: "fixture".into(),
            registry_schema_version: 1,
            family_schema_version: 1,
            registry_revision: 1,
            registry_digest_sha256: "a".repeat(64),
            input_digest_sha256: "b".repeat(64),
            effective_digest_sha256: "c".repeat(64),
            resolution_digest_sha256: "d".repeat(64),
            profile_digest_sha256: None,
            entries: Vec::new(),
            snapshot_digest_sha256: "e".repeat(64),
        });
        assert_eq!(
            EffectiveTunablesView::from_checkpoint(&checkpoint).unwrap_err(),
            EffectiveViewError::HistoricalIdentityOnly
        );
    }

    #[test]
    fn bootstrap_fixed_authority_requires_the_exact_live_owner_value() {
        let owner = provider_discovery_owner_value();
        let binding = RunGenesisFixedAuthorityBindingV2 {
            authority: RunGenesisFixedAuthorityIdV2::ProviderDiscoveryBootstrap,
            owner_value_digest_sha256: fixed_authority_value_digest_sha256(
                "provider_discovery_account_probe_cache_policy",
                FixedAuthorityId::ProviderDiscoveryBootstrap,
                &owner,
            )
            .unwrap(),
        };
        validate_fixed_authority_binding(
            "provider_discovery_account_probe_cache_policy",
            FixedAuthorityId::ProviderDiscoveryBootstrap,
            &owner,
            Some(&binding),
        )
        .expect("the durable binding admits the exact bootstrap owner");
        let mut stale = owner;
        let ResolutionValue::Object { fields } = &mut stale else {
            unreachable!("provider discovery owner is an object")
        };
        fields.insert(
            "positive_ttl_seconds".into(),
            ResolutionValue::Integer { value: 1 },
        );
        assert_eq!(
            validate_fixed_authority_binding(
                "provider_discovery_account_probe_cache_policy",
                FixedAuthorityId::ProviderDiscoveryBootstrap,
                &stale,
                Some(&binding),
            )
            .unwrap_err(),
            EffectiveViewError::InvalidFixedAuthorityEvidence(
                "provider_discovery_account_probe_cache_policy".into()
            )
        );
    }

    #[test]
    fn durable_owner_provenance_must_name_a_canonical_source_binding() {
        let family = iteron_tunables::families()
            .iter()
            .find(|family| family.id == "provider")
            .unwrap();
        let binding = family.source.bindings[0];
        let valid = serde_json::json!({
            "source": {
                "type": "declared",
                "kind": binding.kind,
                "trust": binding.trust,
                "declared_locator": binding.locator,
                "evidence_digest_sha256": "a".repeat(64),
            }
        });
        assert!(canonical_provenance_matches(family, &valid));
        let mut forged = valid;
        forged["source"]["declared_locator"] = serde_json::json!("crates/forged.rs");
        assert!(!canonical_provenance_matches(family, &forged));
    }

    #[test]
    fn session_isolation_labels_are_a_total_runtime_profile_bijection() {
        for (label, expected) in [
            ("interactive", RuntimeProfile::Interactive),
            ("hermetic", RuntimeProfile::Benchmark),
            ("durable", RuntimeProfile::Research),
        ] {
            let view = EffectiveTunablesView::from_test_values(BTreeMap::from([(
                "session_isolation_profile".into(),
                ResolutionValue::Enum {
                    value: label.into(),
                },
            )]));
            let decoded = view.runtime_profile().expect("known label decodes");
            assert_eq!(decoded, expected);
            crate::session_isolation::SessionIsolationPolicy::from_label(label)
                .expect("known label installs a physical policy")
                .validate_profile(decoded)
                .expect("label, runtime profile, and installed policy agree");
        }

        let invalid = EffectiveTunablesView::from_test_values(BTreeMap::from([(
            "session_isolation_profile".into(),
            ResolutionValue::Enum {
                value: "unknown".into(),
            },
        )]));
        assert_eq!(
            invalid.runtime_profile().unwrap_err(),
            EffectiveViewError::UnknownProfile
        );
    }

    #[test]
    fn value_bearing_profile_keeps_its_content_digest_and_decodes_physical_identity() {
        let mut input = iteron_record::resolved_fixture::input();
        input
            .profile
            .as_mut()
            .expect("fixture has a named interactive profile")
            .values
            .push(ProfileValue {
                family: "max_turns".into(),
                as_declared_source: SourceKind::UserConfig,
                value: ResolutionValue::Integer { value: 10 },
            });
        let resolved = iteron_tunables::resolve(input).expect("value-bearing profile resolves");
        let resolved =
            iteron_tunables::with_synthetic_fixed_authority_attestations_for_test(resolved)
                .expect("fixture fixed authorities remain valid");
        let checkpoint = TunablesCheckpoint::V2(
            iteron_record::snapshot_v2_from_resolved(&resolved).expect("resolved set projects"),
        );
        let snapshot = checkpoint.as_v2().expect("V2 checkpoint");
        let content_digest = snapshot
            .profile_digest_sha256
            .as_deref()
            .expect("value-bearing profile keeps immutable content provenance");
        let empty_profile_digest =
            iteron_tunables::runtime_profile_digest(RuntimeProfile::Interactive).unwrap();
        assert_ne!(
            content_digest,
            empty_profile_digest.as_str(),
            "an override must change the content digest instead of impersonating the empty base profile"
        );

        let view = EffectiveTunablesView::from_checkpoint(&checkpoint).unwrap();
        let decoded = view
            .with_getter(RuntimeGetterId::EffectiveCore, || view.runtime_profile())
            .expect("session-isolation identity decodes independently of content digest");
        assert_eq!(decoded, RuntimeProfile::Interactive);
        assert_eq!(checkpoint_runtime_profile(&checkpoint), Some(decoded));

        let mut tampered = checkpoint;
        let TunablesCheckpoint::V2(snapshot) = &mut tampered else {
            unreachable!("test checkpoint is V2")
        };
        let entry = snapshot
            .entries
            .iter_mut()
            .find(|entry| entry.family_id == "session_isolation_profile")
            .expect("session-isolation family is present");
        entry.effective_value = Some(
            serde_json::to_value(ResolutionValue::Enum {
                value: "durable".into(),
            })
            .unwrap(),
        );
        assert_eq!(
            checkpoint_runtime_profile(&tampered),
            None,
            "an invalid checkpoint must not acquire a display identity"
        );
    }
}
