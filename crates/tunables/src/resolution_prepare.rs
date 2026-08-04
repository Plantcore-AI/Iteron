use crate::resolution_types::{
    CatalogSnapshot, ConstraintEvidence, EvidenceState, EvidenceSubject,
    RESOLUTION_INPUT_MAX_BYTES, ResolutionInput, ResolutionValue,
};
use crate::{ActivationPredicate, DefaultResolver, Family, SourceKind, families};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[path = "resolution_prepare_budget.rs"]
mod budget;
#[path = "resolution_prepare_identity.rs"]
mod identity;

pub(crate) struct PreparedInput {
    pub(crate) input: ResolutionInput,
    pub(crate) input_digest_sha256: String,
    pub(crate) profile_digest_sha256: Option<String>,
}

impl PreparedInput {
    pub(crate) fn route(&self, route: &crate::RouteIdentity) -> Option<&crate::RouteCapabilities> {
        self.input
            .runtime
            .admitted_routes
            .iter()
            .find(|candidate| candidate.route == *route)
    }

    pub(crate) fn selected_route(&self) -> Option<&crate::RouteCapabilities> {
        self.input
            .runtime
            .selected_route
            .as_ref()
            .and_then(|route| self.route(route))
    }

    pub(crate) fn constraint(
        &self,
        family: &str,
        field: &str,
        ceiling: crate::ExternalCeiling,
    ) -> Option<&ConstraintEvidence> {
        self.input.constraint_evidence.iter().find(|evidence| {
            evidence.family == family && evidence.field == field && evidence.ceiling == ceiling
        })
    }
}

pub(crate) fn prepare(mut input: ResolutionInput) -> Result<PreparedInput, String> {
    budget::preflight(&input)?;
    identity::exact_registry_identity(&input)?;
    canonicalize(&mut input)?;
    identity::validate_runtime(&input)?;
    validate_candidates(&input)?;
    validate_default_evidence(&input)?;
    validate_activation_evidence(&input)?;
    crate::resolution_constraints::validate_evidence_set(&input)?;
    sort_semantic_vectors(&mut input)?;

    let profile_digest_sha256 = input.profile.as_ref().map(sha256_json).transpose()?;
    let input_bytes = serde_json::to_vec(&input).map_err(|_| "input encoding failed".to_owned())?;
    if input_bytes.len() > RESOLUTION_INPUT_MAX_BYTES {
        return Err("normalized input exceeds the byte ceiling".into());
    }
    let input_digest_sha256 = sha256_bytes(&input_bytes);
    Ok(PreparedInput {
        input,
        input_digest_sha256,
        profile_digest_sha256,
    })
}

fn canonicalize(input: &mut ResolutionInput) -> Result<(), String> {
    if let Some(profile) = &mut input.profile {
        if !budget::safe_machine_id(&profile.profile_id) {
            return Err("profile identity is not a bounded machine identifier".into());
        }
        for candidate in &mut profile.values {
            candidate.family = canonical_family(&candidate.family)?.id.to_owned();
            crate::resolution_value::normalize(&mut candidate.value);
        }
    }
    for candidate in &mut input.declared_values {
        candidate.family = canonical_family(&candidate.family)?.id.to_owned();
        crate::resolution_value::normalize(&mut candidate.value);
    }
    for evidence in &mut input.default_evidence {
        evidence.family = canonical_family(&evidence.family)?.id.to_owned();
        if let EvidenceState::Present { value } = &mut evidence.state {
            crate::resolution_value::normalize(value);
        }
    }
    for evidence in &mut input.constraint_evidence {
        evidence.family = canonical_family(&evidence.family)?.id.to_owned();
        normalize_constraint(&mut evidence.value)?;
    }
    Ok(())
}

fn validate_candidates(input: &ResolutionInput) -> Result<(), String> {
    let catalogs = catalog_map(input);
    let mut declared = BTreeSet::new();
    for candidate in &input.declared_values {
        let family = canonical_family(&candidate.family)?;
        if family.implementation_status == crate::ImplementationStatus::Missing
            || !crate::resolution_value::valid_sha256(&candidate.evidence_digest_sha256)
            || !family
                .source
                .bindings
                .iter()
                .any(|binding| binding.kind == candidate.source)
            || !declared.insert((family.id, candidate.source))
        {
            return Err("declared source is unauthorized, duplicated, or unattested".into());
        }
        validate_family_value(family, &candidate.value, &catalogs)?;
    }

    let mut profile_values = BTreeSet::new();
    if let Some(profile) = &input.profile {
        for candidate in &profile.values {
            let family = canonical_family(&candidate.family)?;
            if family.implementation_status == crate::ImplementationStatus::Missing
                || !matches!(
                    candidate.as_declared_source,
                    SourceKind::UserConfig | SourceKind::ProjectConfig
                )
                || !family
                    .source
                    .bindings
                    .iter()
                    .any(|binding| binding.kind == candidate.as_declared_source)
                || !profile_values.insert((family.id, candidate.as_declared_source))
            {
                return Err("profile source is unauthorized or duplicated".into());
            }
            validate_family_value(family, &candidate.value, &catalogs)?;
        }
    }
    Ok(())
}

fn validate_default_evidence(input: &ResolutionInput) -> Result<(), String> {
    let catalogs = catalog_map(input);
    let mut families_seen = BTreeSet::new();
    for evidence in &input.default_evidence {
        let family = canonical_family(&evidence.family)?;
        if family.implementation_status == crate::ImplementationStatus::Missing
            || !families_seen.insert(family.id)
            || evidence.resolver_id != default_resolver_id(family.default.resolver)
            || !crate::resolution_value::valid_sha256(&evidence.evidence_digest_sha256)
            || !default_subject_matches(family.default.resolver, &evidence.subject, input)
        {
            return Err("default evidence identity, subject, or uniqueness check failed".into());
        }
        match &evidence.state {
            EvidenceState::Present { value } => {
                validate_family_value(family, value, &catalogs)?;
                if let DefaultResolver::GovernedCatalog { catalog_id } = family.default.resolver {
                    let EvidenceSubject::Catalog {
                        catalog_id: subject_id,
                        digest_sha256: subject_digest,
                    } = &evidence.subject
                    else {
                        return Err("governed catalog evidence has the wrong subject".into());
                    };
                    let ResolutionValue::CatalogRef {
                        catalog_id: value_id,
                        digest_sha256: value_digest,
                        ..
                    } = value
                    else {
                        return Err(
                            "governed catalog evidence must carry a catalog reference".into()
                        );
                    };
                    if subject_id != catalog_id
                        || value_id != catalog_id
                        || subject_digest != value_digest
                    {
                        return Err(
                            "governed catalog evidence is not bound to its reference".into()
                        );
                    }
                }
            }
            EvidenceState::Absent { code } | EvidenceState::Unsupported { code }
                if !budget::safe_machine_id(code) =>
            {
                return Err("default evidence code is not a machine identifier".into());
            }
            EvidenceState::Absent { .. } | EvidenceState::Unsupported { .. } => {}
        }
    }
    Ok(())
}

fn validate_activation_evidence(input: &ResolutionInput) -> Result<(), String> {
    let known: BTreeSet<&str> = families()
        .iter()
        .filter_map(|family| match family.activation.predicate {
            ActivationPredicate::RuntimeDerived { seam } => Some(seam),
            _ => None,
        })
        .collect();
    let mut seen = BTreeSet::new();
    for evidence in &input.activation_evidence {
        if !known.contains(evidence.seam.as_str())
            || !seen.insert(evidence.seam.as_str())
            || !crate::resolution_value::valid_sha256(&evidence.subject_digest_sha256)
            || !crate::resolution_value::valid_sha256(&evidence.evidence_digest_sha256)
        {
            return Err("activation evidence is unknown, duplicated, or unattested".into());
        }
    }
    Ok(())
}

fn validate_family_value(
    family: &Family,
    value: &ResolutionValue,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    crate::resolution_value::validate(value, family.value_schema, catalogs)
        .map_err(|_| format!("value for `{}` violates its registry schema", family.id))?;
    Ok(())
}

fn default_subject_matches(
    resolver: DefaultResolver,
    subject: &EvidenceSubject,
    input: &ResolutionInput,
) -> bool {
    match resolver {
        DefaultResolver::Literal => false,
        DefaultResolver::Builtin { .. } => matches!(subject, EvidenceSubject::Global),
        DefaultResolver::ModelMetadata { .. }
        | DefaultResolver::ProviderCapability { .. }
        | DefaultResolver::Transport { .. } => matches!(
            (subject, input.runtime.selected_route.as_ref()),
            (EvidenceSubject::Route { route }, Some(selected)) if route == selected
        ),
        DefaultResolver::RuntimeObservation { field } => matches!(
            subject,
            EvidenceSubject::RuntimeSeam { seam, subject_digest_sha256 }
                if seam == field && crate::resolution_value::valid_sha256(subject_digest_sha256)
        ),
        DefaultResolver::GovernedCatalog { catalog_id } => matches!(
            subject,
            EvidenceSubject::Catalog { catalog_id: actual, digest_sha256 }
                if actual == catalog_id && crate::resolution_value::valid_sha256(digest_sha256)
        ),
        DefaultResolver::Operator { .. } => matches!(
            subject,
            EvidenceSubject::Operator { authority_digest_sha256 }
                if crate::resolution_value::valid_sha256(authority_digest_sha256)
        ),
    }
}

pub(crate) fn default_resolver_id(resolver: DefaultResolver) -> String {
    match resolver {
        DefaultResolver::Literal => "core://tunables/resolvers/literal-v1".into(),
        DefaultResolver::Builtin { resolver_id } => resolver_id.into(),
        DefaultResolver::ModelMetadata { field } => {
            format!("core://tunables/resolvers/model-metadata/{field}-v1")
        }
        DefaultResolver::ProviderCapability { capability } => {
            format!("core://tunables/resolvers/provider-capability/{capability}-v1")
        }
        DefaultResolver::Transport { field } => {
            format!("core://tunables/resolvers/transport/{field}-v1")
        }
        DefaultResolver::RuntimeObservation { field } => {
            format!("core://tunables/resolvers/runtime-observation/{field}-v1")
        }
        DefaultResolver::GovernedCatalog { catalog_id } => catalog_id.into(),
        DefaultResolver::Operator { input_id } => input_id.into(),
    }
}

pub(crate) fn canonical_family(identity: &str) -> Result<&'static Family, String> {
    families()
        .iter()
        .find(|family| family.id == identity || family.aliases.contains(&identity))
        .ok_or_else(|| "input names an unknown tunable family".to_owned())
}

fn catalog_map(input: &ResolutionInput) -> BTreeMap<&str, &CatalogSnapshot> {
    input
        .runtime
        .catalogs
        .iter()
        .map(|catalog| (catalog.catalog_id.as_str(), catalog))
        .collect()
}

fn sort_semantic_vectors(input: &mut ResolutionInput) -> Result<(), String> {
    if let Some(profile) = &mut input.profile {
        profile.values.sort_by(|left, right| {
            (&left.family, left.as_declared_source, &left.value).cmp(&(
                &right.family,
                right.as_declared_source,
                &right.value,
            ))
        });
    }
    input.declared_values.sort_by(|left, right| {
        (
            &left.family,
            left.source,
            &left.evidence_digest_sha256,
            &left.value,
        )
            .cmp(&(
                &right.family,
                right.source,
                &right.evidence_digest_sha256,
                &right.value,
            ))
    });
    sort_by_json(&mut input.default_evidence)?;
    input.activation_evidence.sort_by(|left, right| {
        (
            &left.seam,
            &left.subject_digest_sha256,
            &left.evidence_digest_sha256,
        )
            .cmp(&(
                &right.seam,
                &right.subject_digest_sha256,
                &right.evidence_digest_sha256,
            ))
    });
    sort_by_json(&mut input.constraint_evidence)?;
    sort_by_json(&mut input.runtime.admitted_routes)?;
    input.runtime.catalogs.sort_by(|left, right| {
        (&left.catalog_id, &left.digest_sha256).cmp(&(&right.catalog_id, &right.digest_sha256))
    });
    Ok(())
}

fn sort_by_json<T: Serialize>(values: &mut Vec<T>) -> Result<(), String> {
    let mut keyed = values
        .drain(..)
        .map(|value| {
            serde_json::to_vec(&value)
                .map(|key| (key, value))
                .map_err(|_| "canonical input encoding failed".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    values.extend(keyed.into_iter().map(|(_, value)| value));
    Ok(())
}

fn normalize_constraint(
    value: &mut crate::resolution_types::ConstraintValue,
) -> Result<(), String> {
    use crate::resolution_types::ConstraintValue;
    match value {
        ConstraintValue::UpperBound { value } | ConstraintValue::Exact { value } => {
            crate::resolution_value::normalize(value);
        }
        ConstraintValue::Domain {
            minimum,
            maximum,
            allowed_values,
            required_values,
            preferred,
        } => {
            minimum
                .iter_mut()
                .for_each(crate::resolution_value::normalize);
            maximum
                .iter_mut()
                .for_each(crate::resolution_value::normalize);
            preferred
                .iter_mut()
                .for_each(crate::resolution_value::normalize);
            normalize_set(allowed_values)?;
            normalize_set(required_values)?;
        }
    }
    Ok(())
}

fn normalize_set(values: &mut Option<BTreeSet<ResolutionValue>>) -> Result<(), String> {
    if let Some(values) = values {
        let original_len = values.len();
        *values = std::mem::take(values)
            .into_iter()
            .map(|mut value| {
                crate::resolution_value::normalize(&mut value);
                value
            })
            .collect();
        if values.len() != original_len {
            return Err("constraint set contains semantically duplicate values".into());
        }
    }
    Ok(())
}

fn sha256_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|_| "canonical digest encoding failed".to_owned())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
