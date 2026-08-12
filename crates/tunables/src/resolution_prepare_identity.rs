use crate::resolution_types::{CatalogSnapshot, ResolutionInput, ResolutionValue};
use crate::{EXPECTED_FAMILY_COUNT, StructuredValueDomain, families};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn exact_registry_identity(input: &ResolutionInput) -> Result<(), String> {
    let compiled_digest = crate::registry_digest()
        .map_err(|error| format!("compiled registry identity validation failed: {error:?}"))?;
    if input.schema_version != crate::RESOLUTION_SCHEMA_VERSION
        || input.registry_id != crate::REGISTRY_ID
        || input.registry_revision != crate::REGISTRY_REVISION
        || input.registry_digest != crate::REGISTRY_DIGEST_SHA256
        || input.registry_digest != compiled_digest.value
        || families().len() != EXPECTED_FAMILY_COUNT
    {
        return Err("input registry identity does not match the compiled registry".into());
    }
    if let Some(profile) = &input.profile
        && (profile.schema_version != crate::RESOLUTION_SCHEMA_VERSION
            || profile.registry_revision != crate::REGISTRY_REVISION
            || profile.registry_digest != crate::REGISTRY_DIGEST_SHA256)
    {
        return Err("profile registry identity does not match the compiled registry".into());
    }
    Ok(())
}

pub(super) fn validate_runtime(input: &ResolutionInput) -> Result<(), String> {
    let mut route_ids = BTreeSet::new();
    for route in &input.runtime.admitted_routes {
        validate_route(&route.route)?;
        if !crate::resolution_value::valid_sha256(&route.attestation_digest_sha256)
            || !route_ids.insert(route.route.clone())
        {
            return Err("route identity or attestation is invalid or duplicated".into());
        }
    }
    if let Some(selected) = &input.runtime.selected_route
        && (!route_ids.contains(selected) || validate_route(selected).is_err())
    {
        return Err("selected route is not an exact admitted route".into());
    }

    let mut catalog_ids = BTreeSet::new();
    for catalog in &input.runtime.catalogs {
        if !known_scalar_catalog(&catalog.catalog_id)
            || !catalog_ids.insert(catalog.catalog_id.as_str())
            || catalog.digest_sha256 != catalog_content_digest(catalog)?
            || !scalar_catalog_values_validate(catalog)
        {
            return Err("catalog identity, digest, or uniqueness check failed".into());
        }
    }
    Ok(())
}

pub(crate) fn catalog_content_digest(catalog: &CatalogSnapshot) -> Result<String, String> {
    #[derive(Serialize)]
    struct Payload<'a> {
        canonicalization: &'static str,
        catalog_id: &'a str,
        value_count: usize,
        values: &'a BTreeSet<String>,
    }
    super::sha256_json(&Payload {
        canonicalization: "iteron-tunables-catalog-snapshot-json-v1",
        catalog_id: &catalog.catalog_id,
        value_count: catalog.values.len(),
        values: &catalog.values,
    })
}

fn known_scalar_catalog(id: &str) -> bool {
    crate::SCALAR_CATALOGS
        .iter()
        .any(|catalog| catalog.id == id)
}

fn scalar_catalog_values_validate(catalog: &CatalogSnapshot) -> bool {
    let Some(definition) = crate::SCALAR_CATALOGS
        .iter()
        .find(|definition| definition.id == catalog.catalog_id)
    else {
        return false;
    };
    let schema = crate::ValueSchema {
        version: 1,
        schema_id: "iteron://tunables/internal/catalog-snapshot-value-v1",
        kind: crate::ValueKind::String,
        domain: StructuredValueDomain::Scalar {
            domain: definition.value_domain,
        },
        rules: &[],
    };
    let catalogs = BTreeMap::new();
    catalog.values.iter().all(|value| {
        crate::resolution_value::validate(
            &ResolutionValue::Text {
                value: value.clone(),
            },
            schema,
            &catalogs,
        )
        .is_ok()
    })
}

fn validate_route(route: &crate::RouteIdentity) -> Result<(), String> {
    if super::budget::safe_machine_id(&route.provider_id)
        && super::budget::safe_machine_id(&route.model_id)
        && super::budget::safe_machine_id(&route.route_revision)
        && crate::resolution_value::valid_sha256(&route.catalog_digest_sha256)
    {
        Ok(())
    } else {
        Err("route identity is invalid".into())
    }
}
