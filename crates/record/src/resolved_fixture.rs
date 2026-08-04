//! Public-resolver fixture used to exercise record wrappers with a real `ResolvedTunableSet`.

use core_tunables::{
    ActivationEvidence, ActivationPredicate, CatalogSnapshot, ConstraintEvidence,
    ConstraintProjection, ConstraintRelation, ConstraintValue, CrossFieldRule, DeclaredValue,
    EvidenceSubject, ExternalCeiling, FieldDomain, ImplementationStatus, REGISTRY_DIGEST_SHA256,
    REGISTRY_ID, REGISTRY_REVISION, RESOLUTION_SCHEMA_VERSION, ResolutionInput, ResolutionValue,
    ResolvedTunableSet, RouteCapabilities, RouteIdentity, RuntimeContext, SCALAR_CATALOGS,
    ScalarDomain, StringFormat, StructuredValueDomain, ValueSchema, families, resolve,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub(super) fn resolved() -> ResolvedTunableSet {
    resolve(complete_input()).expect("registry-driven public resolver fixture must remain accepted")
}

fn complete_input() -> ResolutionInput {
    let provider = families()
        .iter()
        .find(|family| family.id == "provider")
        .expect("provider family");
    let model = families()
        .iter()
        .find(|family| family.id == "model")
        .expect("model family");
    let ResolutionValue::Enum { value: provider_id } = sample_schema(provider.value_schema, 1)
    else {
        panic!("provider schema stopped being an enum")
    };
    let ResolutionValue::Enum { value: model_id } = sample_schema(model.value_schema, 2) else {
        panic!("model schema stopped being an enum")
    };
    let route = RouteIdentity {
        provider_id,
        model_id,
        route_revision: "fixture:v1".to_owned(),
        catalog_digest_sha256: DIGEST_A.to_owned(),
    };
    let capabilities: BTreeSet<_> = families()
        .iter()
        .flat_map(|family| family.requirements.capabilities.iter().copied())
        .collect();

    let declared_values = families()
        .iter()
        .filter(|family| family.implementation_status != ImplementationStatus::Missing)
        .map(|family| {
            let source = match family.activation.predicate {
                ActivationPredicate::Configured { sources } => family
                    .source
                    .bindings
                    .iter()
                    .find(|binding| sources.contains(&binding.kind))
                    .unwrap_or_else(|| panic!("{} has no configuring source", family.id)),
                ActivationPredicate::Always | ActivationPredicate::RuntimeDerived { .. } => {
                    family.source.bindings.first().expect("implemented source")
                }
                ActivationPredicate::Unavailable => {
                    panic!("implemented family {} is unavailable", family.id)
                }
            };
            let value = match family.id {
                "provider" => ResolutionValue::Enum {
                    value: route.provider_id.clone(),
                },
                "model" => ResolutionValue::Enum {
                    value: route.model_id.clone(),
                },
                _ => sample_schema(family.value_schema, family.ordinal),
            };
            DeclaredValue {
                family: family.id.to_owned(),
                source: source.kind,
                evidence_digest_sha256: DIGEST_A.to_owned(),
                value,
            }
        })
        .collect::<Vec<_>>();

    let activation_evidence = families()
        .iter()
        .filter_map(|family| match family.activation.predicate {
            ActivationPredicate::RuntimeDerived { seam } => Some(seam),
            ActivationPredicate::Always
            | ActivationPredicate::Configured { .. }
            | ActivationPredicate::Unavailable => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|seam| ActivationEvidence {
            seam: seam.to_owned(),
            subject_digest_sha256: DIGEST_A.to_owned(),
            evidence_digest_sha256: DIGEST_B.to_owned(),
            active: true,
        })
        .collect();

    let constraint_evidence = families()
        .iter()
        .filter(|family| family.implementation_status != ImplementationStatus::Missing)
        .flat_map(|family| {
            let requested = &declared_values
                .iter()
                .find(|value| value.family == family.id)
                .expect("declared family")
                .value;
            family.value_schema.rules.iter().filter_map(|rule| {
                let CrossFieldRule::ExternalCeiling {
                    field,
                    ceiling,
                    projection,
                    relation,
                    ..
                } = *rule
                else {
                    return None;
                };
                let current = match projection {
                    ConstraintProjection::WholeValue => value_at(requested, field)?.clone(),
                    ConstraintProjection::WholeCatalog => requested.clone(),
                };
                let value = match relation {
                    ConstraintRelation::UpperBound => ConstraintValue::UpperBound {
                        value: current.clone(),
                    },
                    ConstraintRelation::Exact => ConstraintValue::Exact {
                        value: current.clone(),
                    },
                    ConstraintRelation::AttestedDomain => {
                        let scalar_verification = ceiling == ExternalCeiling::VerificationFloor
                            && matches!(
                                current,
                                ResolutionValue::Boolean { .. }
                                    | ResolutionValue::Integer { .. }
                                    | ResolutionValue::Decimal { .. }
                                    | ResolutionValue::Text { .. }
                                    | ResolutionValue::Enum { .. }
                            );
                        ConstraintValue::Domain {
                            minimum: scalar_verification.then(|| current.clone()),
                            maximum: None,
                            allowed_values: (!scalar_verification)
                                .then(|| BTreeSet::from([current.clone()])),
                            required_values: None,
                            preferred: (ceiling == ExternalCeiling::ProviderCapability)
                                .then_some(current.clone()),
                        }
                    }
                };
                Some(ConstraintEvidence {
                    family: family.id.to_owned(),
                    field: field.to_owned(),
                    ceiling,
                    subject: constraint_subject(ceiling, &route),
                    evidence_digest_sha256: DIGEST_B.to_owned(),
                    value,
                })
            })
        })
        .collect();

    let catalogs = SCALAR_CATALOGS
        .iter()
        .map(|catalog| {
            let values = (0..=u64::try_from(families().len()).expect("family count"))
                .map(|seed| sample_key(catalog.value_domain, seed))
                .collect();
            catalog_snapshot_values(catalog.id, values)
        })
        .collect();

    ResolutionInput {
        schema_version: RESOLUTION_SCHEMA_VERSION,
        registry_id: REGISTRY_ID.to_owned(),
        registry_revision: REGISTRY_REVISION,
        registry_digest: REGISTRY_DIGEST_SHA256.to_owned(),
        profile: None,
        declared_values,
        default_evidence: Vec::new(),
        activation_evidence,
        constraint_evidence,
        runtime: RuntimeContext {
            admitted_routes: vec![RouteCapabilities {
                route: route.clone(),
                capabilities,
                attestation_digest_sha256: DIGEST_B.to_owned(),
            }],
            selected_route: Some(route),
            catalogs,
        },
    }
}

fn sample_schema(schema: ValueSchema, ordinal: u16) -> ResolutionValue {
    let mut value = sample_value(schema.domain, ordinal);
    for rule in schema.rules {
        match *rule {
            CrossFieldRule::LessOrEqual { left, right } => {
                if let (Some(replacement), Some(_)) =
                    (value_at(&value, left).cloned(), value_at(&value, right))
                {
                    replace_at(&mut value, right, replacement);
                }
            }
            CrossFieldRule::SumLessOrEqual { terms, limit } => {
                let sum = terms
                    .iter()
                    .map(|term| match value_at(&value, term) {
                        Some(ResolutionValue::Integer { value }) => i128::from(*value),
                        _ => panic!("sample sum term `{term}` is not an integer"),
                    })
                    .sum::<i128>();
                if value_at(&value, limit).is_some() {
                    replace_at(
                        &mut value,
                        limit,
                        ResolutionValue::Integer {
                            value: i64::try_from(sum).expect("sample sum"),
                        },
                    );
                }
            }
            CrossFieldRule::Requires { .. }
            | CrossFieldRule::MutuallyExclusive { .. }
            | CrossFieldRule::ExternalCeiling { .. } => {}
        }
    }
    value
}

fn sample_value(domain: StructuredValueDomain, ordinal: u16) -> ResolutionValue {
    match domain {
        StructuredValueDomain::Scalar { domain } => sample_scalar(domain, u64::from(ordinal)),
        StructuredValueDomain::List {
            min_items, item, ..
        } => ResolutionValue::List {
            items: (0..min_items)
                .map(|offset| sample_scalar(item, u64::from(ordinal) + offset))
                .collect(),
        },
        StructuredValueDomain::Map {
            min_entries,
            key,
            value,
            ..
        } => ResolutionValue::Map {
            entries: (0..min_entries)
                .map(|offset| {
                    let seed = u64::from(ordinal) + offset;
                    (sample_key(key, seed), sample_field(value, seed))
                })
                .collect(),
        },
        StructuredValueDomain::Object { fields, .. } => ResolutionValue::Object {
            fields: fields
                .iter()
                .filter(|field| field.required)
                .enumerate()
                .map(|(index, field)| {
                    (
                        field.name.to_owned(),
                        sample_field(field.domain, u64::from(ordinal) + index as u64),
                    )
                })
                .collect(),
        },
        StructuredValueDomain::Catalog {
            catalog_id,
            min_entries,
            ..
        } => ResolutionValue::CatalogRef {
            catalog_id: catalog_id.to_owned(),
            digest_sha256: DIGEST_A.to_owned(),
            entry_count: min_entries,
            canonical_bytes: 0,
        },
    }
}

fn value_at<'a>(value: &'a ResolutionValue, path: &str) -> Option<&'a ResolutionValue> {
    if path == "$" {
        return Some(value);
    }
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let ResolutionValue::Object { fields } = value else {
        return None;
    };
    let child = fields.get(head)?;
    if tail.is_empty() {
        Some(child)
    } else {
        value_at(child, tail)
    }
}

fn replace_at(value: &mut ResolutionValue, path: &str, replacement: ResolutionValue) {
    if path == "$" {
        *value = replacement;
        return;
    }
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let ResolutionValue::Object { fields } = value else {
        panic!("sample path `{path}` does not address an object")
    };
    let child = fields
        .get_mut(head)
        .unwrap_or_else(|| panic!("sample omits `{head}`"));
    if tail.is_empty() {
        *child = replacement;
    } else {
        replace_at(child, tail, replacement);
    }
}

fn sample_field(domain: FieldDomain, seed: u64) -> ResolutionValue {
    match domain {
        FieldDomain::Scalar { domain } => sample_scalar(domain, seed),
        FieldDomain::List {
            min_items, item, ..
        } => ResolutionValue::List {
            items: (0..min_items)
                .map(|offset| sample_scalar(item, seed + offset))
                .collect(),
        },
        FieldDomain::Map {
            min_entries,
            key,
            value,
            ..
        } => ResolutionValue::Map {
            entries: (0..min_entries)
                .map(|offset| {
                    let item_seed = seed + offset;
                    (sample_key(key, item_seed), sample_scalar(value, item_seed))
                })
                .collect(),
        },
        FieldDomain::Object { fields, .. } => ResolutionValue::Object {
            fields: fields
                .iter()
                .filter(|field| field.required)
                .enumerate()
                .map(|(index, field)| {
                    (
                        field.name.to_owned(),
                        sample_field(field.domain, seed + index as u64),
                    )
                })
                .collect(),
        },
    }
}

fn sample_scalar(domain: ScalarDomain, seed: u64) -> ResolutionValue {
    match domain {
        ScalarDomain::Boolean => ResolutionValue::Boolean {
            value: seed.is_multiple_of(2),
        },
        ScalarDomain::Integer { min, max, .. } => ResolutionValue::Integer {
            value: min
                .saturating_add(i64::try_from(seed % 16).expect("small seed"))
                .min(max),
        },
        ScalarDomain::Decimal { min, .. } => ResolutionValue::Decimal { value: min },
        ScalarDomain::Text {
            min_bytes,
            max_bytes,
            format,
        } => ResolutionValue::Text {
            value: sample_string(format, min_bytes, max_bytes, seed),
        },
        ScalarDomain::Enum { values, catalog_id } => ResolutionValue::Enum {
            value: if values.is_empty() {
                assert!(catalog_id.is_some());
                format!("fixture:value-{seed}")
            } else {
                values[usize::try_from(seed).expect("seed") % values.len()].to_owned()
            },
        },
    }
}

fn sample_key(domain: ScalarDomain, seed: u64) -> String {
    match sample_scalar(domain, seed) {
        ResolutionValue::Text { value } | ResolutionValue::Enum { value } => value,
        other => panic!("map key schema is not string-like: {other:?}"),
    }
}

fn sample_string(format: StringFormat, min: u64, max: u64, seed: u64) -> String {
    let mut value = match format {
        StringFormat::Utf8 | StringFormat::Identifier => format!("fixture-{seed}"),
        StringFormat::NamespacedId => format!("fixture:value-{seed}"),
        StringFormat::Uri => format!("fixture://value/{seed}"),
        StringFormat::Command => format!("fixture-command-{seed}"),
        StringFormat::Path => format!("/fixture/path/{seed}"),
        StringFormat::Regex => format!("fixture-{seed}.*"),
        StringFormat::Sha256 => format!("{seed:064x}"),
        StringFormat::Semver => format!("1.0.{seed}"),
    };
    let min = usize::try_from(min).expect("minimum");
    let max = usize::try_from(max).expect("maximum");
    while value.len() < min {
        value.push('x');
    }
    assert!(value.len() <= max, "sample string exceeds schema maximum");
    value
}

fn catalog_snapshot_values(catalog_id: &str, values: BTreeSet<String>) -> CatalogSnapshot {
    #[derive(Serialize)]
    struct Payload<'a> {
        canonicalization: &'static str,
        catalog_id: &'a str,
        value_count: usize,
        values: &'a BTreeSet<String>,
    }
    let digest_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&Payload {
            canonicalization: "core-tunables-catalog-snapshot-json-v1",
            catalog_id,
            value_count: values.len(),
            values: &values,
        })
        .expect("catalog encoding"),
    ));
    CatalogSnapshot {
        catalog_id: catalog_id.to_owned(),
        digest_sha256,
        values,
    }
}

fn constraint_subject(ceiling: ExternalCeiling, route: &RouteIdentity) -> EvidenceSubject {
    match ceiling {
        ExternalCeiling::OperatorAuthority => EvidenceSubject::Operator {
            authority_digest_sha256: DIGEST_A.to_owned(),
        },
        ExternalCeiling::ProviderCapability | ExternalCeiling::ContextWindow => {
            EvidenceSubject::Route {
                route: route.clone(),
            }
        }
        _ => EvidenceSubject::RuntimeSeam {
            seam: match ceiling {
                ExternalCeiling::ParentTurns => "parent_turns",
                ExternalCeiling::ParentTokens => "parent_tokens",
                ExternalCeiling::ParentWall => "parent_wall",
                ExternalCeiling::ParentCost => "parent_cost",
                ExternalCeiling::ToolBudget => "tool_budget",
                ExternalCeiling::ProcessBudget => "process_budget",
                ExternalCeiling::VerificationFloor => "verification_floor",
                ExternalCeiling::TenantScope => "tenant_scope",
                ExternalCeiling::RunBudget => "run_budget",
                ExternalCeiling::BenchmarkProtocol => "benchmark_protocol",
                ExternalCeiling::OperatorAuthority
                | ExternalCeiling::ProviderCapability
                | ExternalCeiling::ContextWindow => unreachable!(),
            }
            .to_owned(),
            subject_digest_sha256: DIGEST_A.to_owned(),
        },
    }
}
