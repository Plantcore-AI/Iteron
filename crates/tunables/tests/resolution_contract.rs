use iteron_tunables::{
    ActivationEvidence, ActivationPredicate, CapabilityRequirement, CatalogSnapshot,
    ConstraintEvidence, ConstraintProjection, ConstraintRelation, ConstraintValue, CrossFieldRule,
    DecimalValue, DeclaredValue, DefaultEvidence, DefaultResolver, EntryOutcome, EvidenceState,
    EvidenceSubject, ExplainError, ExternalCeiling, FailureCode, FieldDomain, ImplementationStatus,
    InactiveCause, ProfileValue, REGISTRY_DIGEST_SHA256, REGISTRY_ID, REGISTRY_REVISION,
    RESOLUTION_SCHEMA_VERSION, RejectionReason, ResolutionInput, ResolutionProfile,
    ResolutionProvenance, ResolutionReport, ResolutionSource, ResolutionValue, ResolvedEntry,
    RouteCapabilities, RouteIdentity, RuleValue, RuntimeContext, SCALAR_CATALOGS, ScalarDomain,
    ShadowedValue, SourceKind, StringFormat, StructuredValueDomain, TunableValue, ValueSchema,
    explain_entry_json, explain_text, families, resolve, resolve_json,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn minimal_input() -> ResolutionInput {
    let route = RouteIdentity {
        provider_id: "glm".to_owned(),
        model_id: "glm-5.2".to_owned(),
        route_revision: "v1".to_owned(),
        catalog_digest_sha256: DIGEST_A.to_owned(),
    };
    let capabilities: BTreeSet<_> = families()
        .iter()
        .flat_map(|family| family.requirements.capabilities.iter().copied())
        .collect();
    let mut catalog_values = BTreeSet::from(["glm".to_owned(), "glm-5.2".to_owned()]);
    for value in families().iter().filter_map(|family| family.default.value) {
        collect_enum_strings(value, &mut catalog_values);
    }
    ResolutionInput {
        schema_version: RESOLUTION_SCHEMA_VERSION,
        registry_id: REGISTRY_ID.to_owned(),
        registry_revision: REGISTRY_REVISION,
        registry_digest: REGISTRY_DIGEST_SHA256.to_owned(),
        profile: None,
        declared_values: Vec::new(),
        default_evidence: Vec::new(),
        activation_evidence: activation_inventory(false),
        constraint_evidence: Vec::new(),
        runtime: RuntimeContext {
            admitted_routes: vec![RouteCapabilities {
                route: route.clone(),
                capabilities,
                attestation_digest_sha256: DIGEST_B.to_owned(),
            }],
            selected_route: Some(route),
            catalogs: SCALAR_CATALOGS
                .iter()
                .map(|catalog| catalog_snapshot_values(catalog.id, catalog_values.clone()))
                .collect(),
        },
    }
}

#[test]
fn prompt_cache_remains_effective_under_an_exact_capability_clamp() {
    let run = |capable: bool, include_constraint: bool| {
        let mut input = minimal_input();
        let selected = input.runtime.selected_route.clone().unwrap();
        let route = input
            .runtime
            .admitted_routes
            .iter_mut()
            .find(|candidate| candidate.route == selected)
            .unwrap();
        if !capable {
            route
                .capabilities
                .remove(&CapabilityRequirement::ProviderPromptCache);
        }
        if include_constraint {
            let effective = ResolutionValue::Boolean { value: capable };
            input.constraint_evidence.push(ConstraintEvidence {
                family: "prompt_cache".to_owned(),
                field: "$".to_owned(),
                ceiling: ExternalCeiling::ProviderCapability,
                subject: EvidenceSubject::Route { route: selected },
                evidence_digest_sha256: DIGEST_B.to_owned(),
                value: ConstraintValue::Domain {
                    minimum: None,
                    maximum: None,
                    allowed_values: Some(BTreeSet::from([effective.clone()])),
                    required_values: None,
                    preferred: Some(effective),
                },
            });
        }
        report_even_when_other_active_families_are_unresolved(input)
            .entries
            .into_iter()
            .find(|entry| entry.family_id == "prompt_cache")
            .unwrap()
    };

    for (capable, expected) in [(false, false), (true, true)] {
        let entry = run(capable, true);
        assert!(matches!(entry.outcome, EntryOutcome::Effective));
        assert_eq!(
            entry.effective,
            Some(ResolutionValue::Boolean { value: expected })
        );
    }

    let missing = run(false, false);
    assert!(matches!(
        missing.outcome,
        EntryOutcome::Unresolved {
            reason: iteron_tunables::UnresolvedReason::ExternalConstraintMissing {
                ceiling: ExternalCeiling::ProviderCapability,
                ..
            }
        }
    ));
}

fn activation_inventory(active: bool) -> Vec<ActivationEvidence> {
    families()
        .iter()
        .filter_map(|family| match family.activation.predicate {
            ActivationPredicate::RuntimeDerived { seam } => Some(ActivationEvidence {
                family: family.id.to_owned(),
                seam: seam.to_owned(),
                subject_digest_sha256: DIGEST_A.to_owned(),
                evidence_digest_sha256: DIGEST_B.to_owned(),
                active,
            }),
            ActivationPredicate::Always
            | ActivationPredicate::Configured { .. }
            | ActivationPredicate::Unavailable => None,
        })
        .collect()
}

fn collect_enum_strings(value: TunableValue, values: &mut BTreeSet<String>) {
    match value {
        TunableValue::Enum { value } => {
            values.insert(value.to_owned());
        }
        TunableValue::List { items } => {
            items
                .iter()
                .copied()
                .for_each(|value| collect_enum_strings(value, values));
        }
        TunableValue::Map { entries } => {
            entries
                .iter()
                .for_each(|entry| collect_enum_strings(entry.value, values));
        }
        TunableValue::Object { fields } => {
            fields
                .iter()
                .for_each(|field| collect_enum_strings(field.value, values));
        }
        TunableValue::Boolean { .. }
        | TunableValue::Integer { .. }
        | TunableValue::Decimal { .. }
        | TunableValue::Text { .. } => {}
    }
}

fn synthetic_report() -> ResolutionReport {
    let mut entries = families()
        .iter()
        .map(|family| {
            if matches!(
                family.implementation_status,
                iteron_tunables::ImplementationStatus::Missing
            ) {
                return ResolvedEntry {
                    ordinal: family.ordinal,
                    family_id: family.id,
                    semantic_key: family.semantic_key,
                    requested: None,
                    effective: None,
                    provenance: None,
                    outcome: EntryOutcome::Unavailable,
                    adjustments: Vec::new(),
                    shadowed: Vec::new(),
                    default: family.default,
                    strategy_slots: family.strategy_slots,
                    optimization: family.optimization,
                    benchmark_relevance: family.benchmark_relevance,
                };
            }
            let value = family.default.value.map_or_else(
                || sample_schema(family.value_schema, family.ordinal),
                owned_value,
            );
            let literal = matches!(family.default.resolver, DefaultResolver::Literal);
            let fallback = family.default.value.is_some() && !literal;
            let resolver_id = resolver_id(family.default.resolver);
            ResolvedEntry {
                ordinal: family.ordinal,
                family_id: family.id,
                semantic_key: family.semantic_key,
                requested: Some(value.clone()),
                effective: Some(value),
                provenance: Some(ResolutionProvenance {
                    source: ResolutionSource::Default {
                        resolver_id,
                        evidence_digest_sha256: (!fallback && !literal)
                            .then(|| DIGEST_B.to_owned()),
                        subject: (!fallback && !literal)
                            .then(|| evidence_subject(family.default.resolver)),
                        fallback,
                    },
                }),
                outcome: EntryOutcome::Effective,
                adjustments: Vec::new(),
                shadowed: Vec::new(),
                default: family.default,
                strategy_slots: family.strategy_slots,
                optimization: family.optimization,
                benchmark_relevance: family.benchmark_relevance,
            }
        })
        .collect::<Vec<_>>();
    repair_report_resolved_set_sum_limits(&mut entries);
    ResolutionReport {
        schema_version: RESOLUTION_SCHEMA_VERSION,
        registry_id: REGISTRY_ID,
        registry_revision: REGISTRY_REVISION,
        registry_digest: REGISTRY_DIGEST_SHA256,
        input_digest_sha256: DIGEST_A.to_owned(),
        effective_digest_sha256: DIGEST_B.to_owned(),
        resolution_digest_sha256: DIGEST_A.to_owned(),
        profile_digest_sha256: None,
        fixed_authority_attestations: Vec::new(),
        entries,
    }
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

fn sample_schema(schema: ValueSchema, ordinal: u16) -> ResolutionValue {
    let mut value = sample_value(schema.domain, ordinal);
    // The repairs interact, and the order rules are declared in is not a dependency order:
    // raising a field to satisfy one rule can violate a rule an earlier pass already settled.
    // One forward pass therefore leaves a sample whose validity depends on declaration order.
    // Iterate to a fixpoint instead, bounded so an unsatisfiable schema fails loudly here
    // rather than spinning.
    let bound = schema.rules.len() + 2;
    for _ in 0..bound {
        let before = value.clone();
        value = apply_sample_rules(value, schema, ordinal);
        if value == before {
            return value;
        }
    }
    panic!(
        "sample repairs for schema `{}` (ordinal {ordinal}) did not converge in {bound} passes",
        schema.schema_id
    )
}

fn sample_truthy(value: &ResolutionValue) -> bool {
    // Mirrors `required_truthy` in the resolver: this is what a `Requires` rule actually demands.
    match value {
        ResolutionValue::Boolean { value } => *value,
        ResolutionValue::Integer { value } => *value != 0,
        ResolutionValue::Decimal { value } => value.coefficient != 0,
        _ => false,
    }
}

fn apply_sample_rules(
    mut value: ResolutionValue,
    schema: ValueSchema,
    ordinal: u16,
) -> ResolutionValue {
    for rule in schema.rules {
        match *rule {
            CrossFieldRule::LessOrEqual { left, right } => {
                // Repair only an actual violation. Copying `left` over `right` unconditionally
                // would undo a `SumLessOrEqual` that already raised `right`, which makes the
                // generated sample depend on the order the rules happen to be declared in.
                let violated = match (value_at(&value, left), value_at(&value, right)) {
                    (
                        Some(ResolutionValue::Integer { value: left_value }),
                        Some(ResolutionValue::Integer { value: right_value }),
                    ) => left_value > right_value,
                    (Some(_), Some(_)) => true,
                    _ => false,
                };
                if violated && let Some(replacement) = value_at(&value, left).cloned() {
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
                            value: i64::try_from(sum).unwrap(),
                        },
                    );
                }
            }
            CrossFieldRule::SumEquals { terms, total } => {
                for (index, term) in terms.iter().enumerate() {
                    replace_at(
                        &mut value,
                        term,
                        ResolutionValue::Decimal {
                            value: if index == 0 {
                                total
                            } else {
                                DecimalValue {
                                    coefficient: 0,
                                    scale: total.scale,
                                }
                            },
                        },
                    );
                }
            }
            CrossFieldRule::Requires {
                if_field,
                equals,
                then_field,
            } => {
                // Repair only an actual violation, for the same reason `LessOrEqual` does above.
                // The resolver demands a truthy `then_field` *only* when the trigger matches, and
                // any truthy value satisfies it. Rewriting to 1 unconditionally clobbered a field
                // another rule had already raised — and did it even when the trigger did not
                // match, so an inert rule could still corrupt the sample.
                let triggered =
                    value_at(&value, if_field).is_some_and(|actual| *actual == rule_value(equals));
                let satisfied = value_at(&value, then_field).is_some_and(sample_truthy);
                if triggered && !satisfied {
                    let replacement = match value_at(&value, then_field) {
                        Some(ResolutionValue::Boolean { .. }) => {
                            ResolutionValue::Boolean { value: true }
                        }
                        Some(ResolutionValue::Integer { .. }) => {
                            ResolutionValue::Integer { value: 1 }
                        }
                        Some(ResolutionValue::Decimal { value }) => ResolutionValue::Decimal {
                            value: DecimalValue {
                                coefficient: 1,
                                scale: value.scale,
                            },
                        },
                        _ => continue,
                    };
                    replace_at(&mut value, then_field, replacement);
                }
            }
            CrossFieldRule::MutuallyExclusive { .. }
            | CrossFieldRule::ResolvedSetSumLessOrEqual { .. }
            | CrossFieldRule::ExternalCeiling { .. } => {}
            CrossFieldRule::MapEntryDomain { key, domain } => {
                if value_at(&value, key).is_some() {
                    replace_at(&mut value, key, sample_scalar(domain, u64::from(ordinal)));
                }
            }
            CrossFieldRule::AtLeastOneNonZero { fields } => {
                let replacement = match value_at(&value, fields[0]) {
                    Some(ResolutionValue::Integer { .. }) => ResolutionValue::Integer { value: 1 },
                    _ => ResolutionValue::Decimal {
                        value: iteron_tunables::DecimalValue {
                            coefficient: 1,
                            scale: 0,
                        },
                    },
                };
                replace_at(&mut value, fields[0], replacement);
            }
            CrossFieldRule::Equals {
                field,
                value: expected,
            } => replace_at(&mut value, field, rule_value(expected)),
        }
    }
    value
}

fn value_at<'a>(value: &'a ResolutionValue, path: &str) -> Option<&'a ResolutionValue> {
    if path == "$" {
        return Some(value);
    }
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let fields = match value {
        ResolutionValue::Object { fields } => fields,
        ResolutionValue::Map { entries } => entries,
        _ => return None,
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
    let fields = match value {
        ResolutionValue::Object { fields } => fields,
        ResolutionValue::Map { entries } => entries,
        _ => panic!("sample path `{path}` does not address an object or map"),
    };
    if tail.is_empty() {
        fields.insert(head.to_owned(), replacement);
    } else {
        let child = fields
            .get_mut(head)
            .unwrap_or_else(|| panic!("sample omits `{head}`"));
        replace_at(child, tail, replacement);
    }
}

fn repair_resolved_set_sum_limits(values: &mut [DeclaredValue]) {
    for family in families() {
        for rule in family.value_schema.rules {
            let CrossFieldRule::ResolvedSetSumLessOrEqual { terms, limit, .. } = *rule else {
                continue;
            };
            let sum = terms
                .iter()
                .map(|term| {
                    let value = values
                        .iter()
                        .find(|value| value.family == term.family)
                        .unwrap_or_else(|| panic!("resolved-set term family `{}`", term.family));
                    match value_at(&value.value, term.path) {
                        Some(ResolutionValue::Integer { value }) => i128::from(*value),
                        _ => panic!(
                            "resolved-set term `{}:{}` is not an integer",
                            term.family, term.path
                        ),
                    }
                })
                .try_fold(0i128, i128::checked_add)
                .expect("fixture resolved-set sum");
            let owner = values
                .iter_mut()
                .find(|value| value.family == limit.family)
                .unwrap_or_else(|| panic!("resolved-set limit family `{}`", limit.family));
            replace_at(
                &mut owner.value,
                limit.path,
                ResolutionValue::Integer {
                    value: i64::try_from(sum).expect("fixture resolved-set sum fits i64"),
                },
            );
        }
    }
}

fn repair_report_resolved_set_sum_limits(entries: &mut [ResolvedEntry]) {
    for family in families() {
        for rule in family.value_schema.rules {
            let CrossFieldRule::ResolvedSetSumLessOrEqual { terms, limit, .. } = *rule else {
                continue;
            };
            let sum = terms
                .iter()
                .map(|term| {
                    let entry = entries
                        .iter()
                        .find(|entry| entry.family_id == term.family)
                        .unwrap_or_else(|| panic!("resolved-set term family `{}`", term.family));
                    match entry
                        .effective
                        .as_ref()
                        .and_then(|value| value_at(value, term.path))
                    {
                        Some(ResolutionValue::Integer { value }) => i128::from(*value),
                        _ => panic!(
                            "resolved-set term `{}:{}` is not an effective integer",
                            term.family, term.path
                        ),
                    }
                })
                .sum::<i128>();
            let replacement = ResolutionValue::Integer {
                value: i64::try_from(sum).expect("resolved-set report sum"),
            };
            let entry = entries
                .iter_mut()
                .find(|entry| entry.family_id == limit.family)
                .unwrap_or_else(|| panic!("resolved-set limit family `{}`", limit.family));
            for value in [&mut entry.requested, &mut entry.effective] {
                replace_at(
                    value.as_mut().expect("resolved-set limit effective value"),
                    limit.path,
                    replacement.clone(),
                );
            }
        }
    }
}

fn rule_value(value: RuleValue) -> ResolutionValue {
    match value {
        RuleValue::Boolean { value } => ResolutionValue::Boolean { value },
        RuleValue::Integer { value } => ResolutionValue::Integer { value },
        RuleValue::Decimal { value } => ResolutionValue::Decimal { value },
        RuleValue::Enum { value } => ResolutionValue::Enum {
            value: value.to_owned(),
        },
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
                .saturating_add(i64::try_from(seed % 16).unwrap())
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
                values[usize::try_from(seed).unwrap() % values.len()].to_owned()
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
        StringFormat::Utf8 => format!("fixture-{seed}"),
        StringFormat::Identifier => format!("fixture-{seed}"),
        StringFormat::NamespacedId => format!("fixture:value-{seed}"),
        StringFormat::Uri => format!("fixture://value/{seed}"),
        StringFormat::Command => format!("fixture-command-{seed}"),
        StringFormat::Path => format!("/fixture/path/{seed}"),
        StringFormat::Regex => format!("fixture-{seed}.*"),
        StringFormat::Sha256 => format!("{seed:064x}"),
        StringFormat::Semver => format!("1.0.{seed}"),
    };
    let min = usize::try_from(min).unwrap();
    let max = usize::try_from(max).unwrap();
    while value.len() < min {
        value.push('x');
    }
    assert!(value.len() <= max, "sample string exceeds schema maximum");
    value
}

fn owned_value(value: TunableValue) -> ResolutionValue {
    match value {
        TunableValue::Boolean { value } => ResolutionValue::Boolean { value },
        TunableValue::Integer { value } => ResolutionValue::Integer { value },
        TunableValue::Decimal { value } => ResolutionValue::Decimal { value },
        TunableValue::Text { value } => ResolutionValue::Text {
            value: value.to_owned(),
        },
        TunableValue::Enum { value } => ResolutionValue::Enum {
            value: value.to_owned(),
        },
        TunableValue::List { items } => ResolutionValue::List {
            items: items.iter().copied().map(owned_value).collect(),
        },
        TunableValue::Map { entries } => ResolutionValue::Map {
            entries: entries
                .iter()
                .map(|entry| (entry.name.to_owned(), owned_value(entry.value)))
                .collect(),
        },
        TunableValue::Object { fields } => ResolutionValue::Object {
            fields: fields
                .iter()
                .map(|field| (field.name.to_owned(), owned_value(field.value)))
                .collect(),
        },
    }
}

fn resolver_id(resolver: DefaultResolver) -> String {
    match resolver {
        DefaultResolver::Literal => "iteron://tunables/resolvers/literal-v1".to_owned(),
        DefaultResolver::Builtin { resolver_id } => resolver_id.to_owned(),
        DefaultResolver::ModelMetadata { field } => {
            format!("iteron://tunables/resolvers/model-metadata/{field}-v1")
        }
        DefaultResolver::ProviderCapability { capability } => {
            format!("iteron://tunables/resolvers/provider-capability/{capability}-v1")
        }
        DefaultResolver::Transport { field } => {
            format!("iteron://tunables/resolvers/transport/{field}-v1")
        }
        DefaultResolver::RuntimeObservation { field } => {
            format!("iteron://tunables/resolvers/runtime-observation/{field}-v1")
        }
        DefaultResolver::GovernedCatalog { catalog_id } => catalog_id.to_owned(),
        DefaultResolver::Operator { input_id } => input_id.to_owned(),
    }
}

fn evidence_subject(resolver: DefaultResolver) -> EvidenceSubject {
    match resolver {
        DefaultResolver::Builtin { .. } => EvidenceSubject::Global,
        DefaultResolver::ModelMetadata { .. }
        | DefaultResolver::ProviderCapability { .. }
        | DefaultResolver::Transport { .. } => EvidenceSubject::Route {
            route: RouteIdentity {
                provider_id: "fixture:provider".to_owned(),
                model_id: "fixture:model".to_owned(),
                route_revision: "v1".to_owned(),
                catalog_digest_sha256: DIGEST_A.to_owned(),
            },
        },
        DefaultResolver::RuntimeObservation { field } => EvidenceSubject::RuntimeSeam {
            seam: field.to_owned(),
            subject_digest_sha256: DIGEST_A.to_owned(),
        },
        DefaultResolver::GovernedCatalog { catalog_id } => EvidenceSubject::Catalog {
            catalog_id: catalog_id.to_owned(),
            digest_sha256: DIGEST_A.to_owned(),
        },
        DefaultResolver::Operator { .. } => EvidenceSubject::Operator {
            authority_digest_sha256: DIGEST_A.to_owned(),
        },
        DefaultResolver::Literal => panic!("literal defaults never require evidence"),
    }
}

fn catalog_snapshot(catalog_id: &str, value: &str) -> CatalogSnapshot {
    catalog_snapshot_values(catalog_id, BTreeSet::from([value.to_owned()]))
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
            canonicalization: "iteron-tunables-catalog-snapshot-json-v1",
            catalog_id,
            value_count: values.len(),
            values: &values,
        })
        .unwrap(),
    ));
    CatalogSnapshot {
        catalog_id: catalog_id.to_owned(),
        digest_sha256,
        values,
    }
}

fn complete_success_input() -> ResolutionInput {
    let provider = families()
        .iter()
        .find(|family| family.id == "provider")
        .unwrap();
    let model = families()
        .iter()
        .find(|family| family.id == "model")
        .unwrap();
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

    let mut declared_values = families()
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
                    family.source.bindings.first().unwrap()
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
                _ if source.kind == SourceKind::Builtin
                    && matches!(family.default.resolver, DefaultResolver::Literal) =>
                {
                    owned_value(
                        family
                            .default
                            .value
                            .expect("literal family has one canonical embedded value"),
                    )
                }
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
    repair_resolved_set_sum_limits(&mut declared_values);

    let activation_evidence = activation_inventory(true);

    let constraint_evidence = families()
        .iter()
        .filter(|family| family.implementation_status != ImplementationStatus::Missing)
        .flat_map(|family| {
            let requested = &declared_values
                .iter()
                .find(|value| value.family == family.id)
                .unwrap()
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

    let default_evidence = families()
        .iter()
        .filter(|family| {
            family.implementation_status != ImplementationStatus::Missing
                && matches!(family.default.resolver, DefaultResolver::Builtin { .. })
        })
        .take(2)
        .map(|family| DefaultEvidence {
            family: family.id.to_owned(),
            resolver_id: resolver_id(family.default.resolver),
            subject: EvidenceSubject::Global,
            evidence_digest_sha256: DIGEST_A.to_owned(),
            state: EvidenceState::Present {
                value: sample_schema(family.value_schema, family.ordinal),
            },
        })
        .collect();

    let catalogs = SCALAR_CATALOGS
        .iter()
        .map(|catalog| {
            let values = (0..=u64::try_from(families().len()).unwrap())
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
        profile: Some(ResolutionProfile {
            schema_version: RESOLUTION_SCHEMA_VERSION,
            profile_id: "fixture:complete".to_owned(),
            registry_revision: REGISTRY_REVISION,
            registry_digest: REGISTRY_DIGEST_SHA256.to_owned(),
            values: ["max_turns", "max_wall_secs"]
                .into_iter()
                .map(|id| {
                    let family = families().iter().find(|family| family.id == id).unwrap();
                    let source = family
                        .source
                        .bindings
                        .iter()
                        .find(|binding| {
                            matches!(
                                binding.kind,
                                SourceKind::UserConfig | SourceKind::ProjectConfig
                            )
                        })
                        .unwrap();
                    ProfileValue {
                        family: id.to_owned(),
                        as_declared_source: source.kind,
                        value: sample_schema(family.value_schema, family.ordinal),
                    }
                })
                .collect(),
        }),
        declared_values,
        default_evidence,
        activation_evidence,
        constraint_evidence,
        runtime: RuntimeContext {
            admitted_routes: vec![
                RouteCapabilities {
                    route: route.clone(),
                    capabilities: capabilities.clone(),
                    attestation_digest_sha256: DIGEST_B.to_owned(),
                },
                RouteCapabilities {
                    route: RouteIdentity {
                        route_revision: "fixture:v2".to_owned(),
                        ..route.clone()
                    },
                    capabilities,
                    attestation_digest_sha256: DIGEST_A.to_owned(),
                },
            ],
            selected_route: Some(route),
            catalogs,
        },
    }
}

/// Move a family's external-ceiling attestation onto `value`.
///
/// `complete_success_input` attests exactly the declared value of every family; that is what makes
/// the fixture coherent rather than merely large. A test that changes which value wins for a
/// family — by forging a candidate, or by dropping the declaration so a default takes over — has
/// to move the attestation with it. Otherwise it asserts against an operator who never authorized
/// the value under test, and the resolver rejects on the stale domain long before reaching
/// whatever the test meant to exercise.
fn reattest_external_ceiling(input: &mut ResolutionInput, family: &str, value: &ResolutionValue) {
    for evidence in input
        .constraint_evidence
        .iter_mut()
        .filter(|evidence| evidence.family == family)
    {
        let Some(projected) = value_at(value, &evidence.field).cloned() else {
            continue;
        };
        match &mut evidence.value {
            ConstraintValue::UpperBound { value } | ConstraintValue::Exact { value } => {
                *value = projected;
            }
            ConstraintValue::Domain {
                minimum,
                allowed_values,
                preferred,
                ..
            } => {
                // Replace only the facets this ceiling actually attested, so the shape of the
                // evidence stays what `complete_success_input` built for that ceiling kind.
                if minimum.is_some() {
                    *minimum = Some(projected.clone());
                }
                if allowed_values.is_some() {
                    *allowed_values = Some(BTreeSet::from([projected.clone()]));
                }
                if preferred.is_some() {
                    *preferred = Some(projected);
                }
            }
        }
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

#[test]
fn complete_registry_driven_resolution_succeeds_and_explains_all_active_families() {
    let input = complete_success_input();
    let active_rule_count = families()
        .iter()
        .filter(|family| family.implementation_status != ImplementationStatus::Missing)
        .flat_map(|family| {
            let requested = &input
                .declared_values
                .iter()
                .find(|value| value.family == family.id)
                .unwrap()
                .value;
            family.value_schema.rules.iter().filter(|rule| match rule {
                CrossFieldRule::ExternalCeiling {
                    field, projection, ..
                } => match projection {
                    ConstraintProjection::WholeValue => value_at(requested, field).is_some(),
                    ConstraintProjection::WholeCatalog => true,
                },
                _ => false,
            })
        })
        .count();
    assert_eq!(input.constraint_evidence.len(), active_rule_count);
    let mut permuted = input.clone();
    permuted.profile.as_mut().unwrap().values.reverse();
    permuted.declared_values.reverse();
    permuted.default_evidence.reverse();
    permuted.activation_evidence.reverse();
    permuted.constraint_evidence.reverse();
    permuted.runtime.admitted_routes.reverse();
    permuted.runtime.catalogs.reverse();
    let first = resolve(input).unwrap();
    let second = resolve(permuted).unwrap();
    assert_eq!(first, second);
    let report = first.report();
    assert_eq!(report.entries.len(), iteron_tunables::EXPECTED_FAMILY_COUNT);
    for (entry, family) in report.entries.iter().zip(families()) {
        if family.implementation_status == ImplementationStatus::Missing {
            assert!(matches!(entry.outcome, EntryOutcome::Unavailable));
        } else {
            assert!(matches!(entry.outcome, EntryOutcome::Effective));
            assert!(entry.effective.is_some());
        }
    }
    for (family_id, optional_field) in [
        ("selective_restore_scope", "paths"),
        ("per_agent_memory_scope", "scope_id"),
    ] {
        let entry = report
            .entries
            .iter()
            .find(|entry| entry.family_id == family_id)
            .unwrap();
        let Some(ResolutionValue::Object { fields }) = entry.requested.as_ref() else {
            panic!("{family_id} stopped being an object")
        };
        assert!(!fields.contains_key(optional_field));
        assert!(matches!(entry.outcome, EntryOutcome::Effective));
    }
    assert!(explain_text(report).unwrap().lines().count() >= 163);
    let provider: Value =
        serde_json::from_str(&explain_entry_json(report, "provider").unwrap()).unwrap();
    assert_eq!(provider["entry"]["state"], "effective");
    for digest in [
        &report.input_digest_sha256,
        &report.effective_digest_sha256,
        &report.resolution_digest_sha256,
    ] {
        assert_eq!(digest.len(), 64);
    }
}

#[test]
fn resolved_context_sum_accepts_exact_boundary_and_rejects_one_token_over() {
    let boundary = complete_success_input();
    let accepted = resolve(boundary.clone()).expect("exact context-window boundary must resolve");
    let rule = families()
        .iter()
        .flat_map(|family| family.value_schema.rules)
        .find_map(|rule| match rule {
            CrossFieldRule::ResolvedSetSumLessOrEqual { terms, limit, .. } => {
                Some((*terms, *limit))
            }
            _ => None,
        })
        .expect("canonical resolved-set context rule");
    let sum = rule
        .0
        .iter()
        .map(|path| resolved_integer(accepted.report(), *path))
        .try_fold(0i128, i128::checked_add)
        .expect("context component sum");
    assert_eq!(sum, resolved_integer(accepted.report(), rule.1));

    let mut over = boundary;
    let context = over
        .declared_values
        .iter_mut()
        .find(|value| value.family == "context_window_override_reserve")
        .expect("context-window declaration");
    let Some(ResolutionValue::Integer { value }) =
        value_at(&context.value, "instruction_budget_tokens").cloned()
    else {
        panic!("instruction budget stopped being an integer")
    };
    replace_at(
        &mut context.value,
        "instruction_budget_tokens",
        ResolutionValue::Integer { value: value + 1 },
    );
    let rejected = resolve(over).expect_err("one-token context over-sum must fail closed");
    assert_eq!(rejected.code, FailureCode::ActiveResolutionFailed);
    assert_eq!(
        rejected
            .failures
            .iter()
            .find(|failure| failure.family_id == "context_window_override_reserve")
            .map(|failure| failure.reason_code),
        Some("cross_field_rule_rejected")
    );
    let entry = rejected
        .report
        .as_ref()
        .expect("atomic failure report")
        .entries
        .iter()
        .find(|entry| entry.family_id == "context_window_override_reserve")
        .expect("context-window result");
    assert!(matches!(
        entry.outcome,
        EntryOutcome::Rejected {
            reason: RejectionReason::CrossFieldRule {
                detail_code: "resolved_set_sum_exceeds_limit"
            }
        }
    ));
}

#[test]
fn enabled_hedging_requires_a_positive_duplicate_bound_and_idempotent_transport() {
    for (field, invalid) in [
        ("max_duplicates", ResolutionValue::Integer { value: 0 }),
        ("idempotent_only", ResolutionValue::Boolean { value: false }),
    ] {
        let mut input = complete_success_input();
        let hedge = input
            .declared_values
            .iter_mut()
            .find(|value| value.family == "hedged_request_policy")
            .expect("hedge declaration");
        replace_at(
            &mut hedge.value,
            "enabled",
            ResolutionValue::Boolean { value: true },
        );
        replace_at(&mut hedge.value, field, invalid);
        let rejected = resolve(input).expect_err("unsafe enabled hedge must fail closed");
        assert_eq!(rejected.code, FailureCode::InvalidInput);
        assert!(
            rejected
                .detail
                .contains("value for `hedged_request_policy` violates its registry schema"),
            "field {field} must be governed by the canonical schema, not only the runtime decoder: {}",
            rejected.detail
        );
    }
}

#[test]
fn disabled_hedge_policy_does_not_invent_a_provider_hedging_capability() {
    let mut input = complete_success_input();
    input.runtime.admitted_routes[0]
        .capabilities
        .remove(&iteron_tunables::CapabilityRequirement::ProviderHedging);
    let hedge = input
        .declared_values
        .iter_mut()
        .find(|value| value.family == "hedged_request_policy")
        .expect("hedge declaration");
    replace_at(
        &mut hedge.value,
        "enabled",
        ResolutionValue::Boolean { value: false },
    );

    let resolved = resolve(input).expect("a disabled policy needs no physical hedge capability");
    let hedge = resolved
        .report()
        .entries
        .iter()
        .find(|entry| entry.family_id == "hedged_request_policy")
        .expect("hedge result");
    assert!(matches!(hedge.outcome, EntryOutcome::Effective));
}

#[test]
fn enabled_hedge_policy_fails_closed_without_provider_hedging_capability() {
    let mut input = complete_success_input();
    input.runtime.admitted_routes[0]
        .capabilities
        .remove(&iteron_tunables::CapabilityRequirement::ProviderHedging);
    let hedge = input
        .declared_values
        .iter_mut()
        .find(|value| value.family == "hedged_request_policy")
        .expect("hedge declaration");
    replace_at(
        &mut hedge.value,
        "enabled",
        ResolutionValue::Boolean { value: true },
    );
    replace_at(
        &mut hedge.value,
        "max_duplicates",
        ResolutionValue::Integer { value: 1 },
    );
    replace_at(
        &mut hedge.value,
        "idempotent_only",
        ResolutionValue::Boolean { value: true },
    );

    let failure = resolve(input).expect_err("an enabled physical hedge requires attestation");
    let entry = failure
        .report
        .expect("atomic failure report")
        .entries
        .into_iter()
        .find(|entry| entry.family_id == "hedged_request_policy")
        .expect("hedge result");
    assert!(matches!(
        entry.outcome,
        EntryOutcome::Rejected {
            reason: RejectionReason::ProviderRequirement {
                missing_capabilities,
                ..
            }
        } if missing_capabilities == vec![iteron_tunables::CapabilityRequirement::ProviderHedging]
    ));
}

#[test]
fn failover_taxonomy_without_a_fallback_chain_needs_no_failover_capability() {
    let mut input = complete_success_input();
    input.runtime.admitted_routes[0]
        .capabilities
        .remove(&iteron_tunables::CapabilityRequirement::ProviderFailover);
    input
        .declared_values
        .retain(|value| value.family != "model_fallback_chain");

    let resolved = resolve(input).expect("an inert taxonomy needs no physical failover capability");
    let taxonomy = resolved
        .report()
        .entries
        .iter()
        .find(|entry| entry.family_id == "failover_eligible_error_taxonomy")
        .expect("taxonomy result");
    assert!(matches!(taxonomy.outcome, EntryOutcome::Effective));
}

#[test]
fn offline_builtin_literal_candidates_cannot_override_registry_bytes() {
    for (family, forged) in [
        (
            "effort",
            ResolutionValue::Enum {
                value: "high".to_owned(),
            },
        ),
        (
            "model_fallback_chain",
            ResolutionValue::List {
                items: vec![ResolutionValue::Enum {
                    value: "fixture:fallback".to_owned(),
                }],
            },
        ),
    ] {
        let mut input = complete_success_input();
        let candidate = input
            .declared_values
            .iter_mut()
            .find(|candidate| candidate.family == family)
            .expect("complete fixture declares every active family");
        candidate.source = SourceKind::Builtin;
        candidate.value = forged;
        assert_eq!(
            resolve(input)
                .expect_err("Builtin cannot replace an embedded literal")
                .code,
            FailureCode::InvalidInput
        );
    }

    let mut input = complete_success_input();
    for (family, exact) in [
        (
            "effort",
            ResolutionValue::Enum {
                value: "medium".to_owned(),
            },
        ),
        (
            "model_fallback_chain",
            ResolutionValue::List { items: Vec::new() },
        ),
    ] {
        let candidate = input
            .declared_values
            .iter_mut()
            .find(|candidate| candidate.family == family)
            .expect("complete fixture declares every active family");
        candidate.source = SourceKind::Builtin;
        candidate.value = exact.clone();
        reattest_external_ceiling(&mut input, family, &exact);
    }
    resolve(input).expect("exact embedded literals remain admissible");
}

#[test]
fn failover_taxonomy_with_a_fallback_chain_fails_closed_without_capability() {
    let mut input = complete_success_input();
    // Strip the capability from every admitted route, not just the selected one. An
    // `AnyAdmittedRoute` requirement falls back to any other admitted route that still carries
    // it, and the complete fixture admits two, so clearing only `[0]` leaves the requirement
    // satisfiable and the taxonomy resolves instead of failing closed.
    for route in &mut input.runtime.admitted_routes {
        route
            .capabilities
            .remove(&iteron_tunables::CapabilityRequirement::ProviderFailover);
    }
    let chain = ResolutionValue::List {
        items: vec![ResolutionValue::Enum {
            value: "fixture:value-0".to_owned(),
        }],
    };
    let fallback = input
        .declared_values
        .iter_mut()
        .find(|value| value.family == "model_fallback_chain")
        .expect("fallback declaration");
    fallback.value = chain.clone();
    reattest_external_ceiling(&mut input, "model_fallback_chain", &chain);

    let failure = resolve(input).expect_err("physical failover requires route attestation");
    let entry = failure
        .report
        .expect("atomic failure report")
        .entries
        .into_iter()
        .find(|entry| entry.family_id == "failover_eligible_error_taxonomy")
        .expect("taxonomy result");
    assert!(matches!(
        entry.outcome,
        EntryOutcome::Rejected {
            reason: RejectionReason::ProviderRequirement {
                missing_capabilities,
                ..
            }
        } if missing_capabilities == vec![iteron_tunables::CapabilityRequirement::ProviderFailover]
    ));
}

#[test]
fn provider_objective_weights_are_normalized_by_the_canonical_schema() {
    let mut input = complete_success_input();
    let weights = input
        .declared_values
        .iter_mut()
        .find(|value| value.family == "route_quality_cost_latency_objective_weights")
        .expect("objective weights declaration");
    replace_at(
        &mut weights.value,
        "quality",
        ResolutionValue::Decimal {
            value: DecimalValue {
                coefficient: 1,
                scale: 0,
            },
        },
    );
    replace_at(
        &mut weights.value,
        "cost",
        ResolutionValue::Decimal {
            value: DecimalValue {
                coefficient: 1,
                scale: 0,
            },
        },
    );
    let rejected = resolve(input).expect_err("non-normalized objective weights must fail closed");
    assert_eq!(rejected.code, FailureCode::InvalidInput);
    assert!(
        rejected.detail.contains(
            "value for `route_quality_cost_latency_objective_weights` violates its registry schema"
        ),
        "the canonical schema must reject the non-normalized objective before runtime decode: {}",
        rejected.detail
    );
}

fn resolved_integer(report: &ResolutionReport, path: iteron_tunables::ResolvedValuePath) -> i128 {
    let entry = report
        .entries
        .iter()
        .find(|entry| entry.family_id == path.family)
        .unwrap_or_else(|| panic!("resolved family `{}`", path.family));
    match value_at(
        entry.effective.as_ref().expect("effective value"),
        path.path,
    ) {
        Some(ResolutionValue::Integer { value }) => i128::from(*value),
        _ => panic!(
            "resolved path `{}:{}` is not an integer",
            path.family, path.path
        ),
    }
}

#[test]
fn canonical_registry_has_no_ambient_runtime_activation_channel() {
    assert!(families().iter().all(|family| !matches!(
        family.activation.predicate,
        ActivationPredicate::RuntimeDerived { .. }
    )));
    let resolved = resolve(complete_success_input()).unwrap();
    for family in ["retry_backoff_base", "retry_backoff_cap"] {
        let entry = resolved
            .report()
            .entries
            .iter()
            .find(|entry| entry.family_id == family)
            .unwrap();
        assert!(matches!(entry.outcome, EntryOutcome::Effective));
    }
}

#[test]
fn optional_constrained_fields_need_evidence_only_when_present() {
    // `per_agent_memory_scope`/`scope_id` is the registry's only other optional externally
    // constrained field, and it cannot be reached this way: that family binds `Builtin` alone, a
    // `Builtin` candidate must equal the embedded literal byte for byte, and that literal carries
    // only `mode` and `inherit_parent`. Adding `scope_id` to it is refused at input validation by
    // the same invariant `offline_builtin_literal_candidates_cannot_override_registry_bytes`
    // pins, so resolution never reaches the per-family stage this test is about. Covering the
    // `TenantScope` ceiling needs a family that can carry the field, not a weaker assertion here.
    let mut input = complete_success_input();
    for (family_id, field, value) in [(
        "selective_restore_scope",
        "paths",
        ResolutionValue::List {
            items: vec![ResolutionValue::Text {
                value: "/fixture/path".to_owned(),
            }],
        },
    )] {
        let candidate = input
            .declared_values
            .iter_mut()
            .find(|candidate| candidate.family == family_id)
            .unwrap();
        let ResolutionValue::Object { fields } = &mut candidate.value else {
            panic!("{family_id} stopped being an object")
        };
        fields.insert(field.to_owned(), value);
    }
    let failure = resolve(input).unwrap_err();
    let report = failure.report.unwrap();
    for (family_id, field, ceiling) in [(
        "selective_restore_scope",
        "paths",
        ExternalCeiling::OperatorAuthority,
    )] {
        let entry = report
            .entries
            .iter()
            .find(|entry| entry.family_id == family_id)
            .unwrap();
        assert!(matches!(
            &entry.outcome,
            EntryOutcome::Unresolved {
                reason: iteron_tunables::UnresolvedReason::ExternalConstraintMissing {
                    field: actual_field,
                    ceiling: actual_ceiling,
                }
            } if actual_field == field && *actual_ceiling == ceiling
        ));
    }
}

#[test]
fn operator_whole_map_authority_cannot_be_bypassed_by_matching_only_the_key() {
    let mut input = minimal_input();
    let requested = ResolutionValue::Map {
        entries: [(
            "fixture:tool".to_owned(),
            ResolutionValue::Enum {
                value: "allow".to_owned(),
            },
        )]
        .into_iter()
        .collect(),
    };
    let allowed_alternative = ResolutionValue::Map {
        entries: [(
            "fixture:tool".to_owned(),
            ResolutionValue::Enum {
                value: "deny".to_owned(),
            },
        )]
        .into_iter()
        .collect(),
    };
    input.declared_values.push(DeclaredValue {
        family: "permission_rules".to_owned(),
        source: SourceKind::UserConfig,
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: requested.clone(),
    });
    input.constraint_evidence.push(ConstraintEvidence {
        family: "permission_rules".to_owned(),
        field: "$".to_owned(),
        ceiling: ExternalCeiling::OperatorAuthority,
        subject: EvidenceSubject::Operator {
            authority_digest_sha256: DIGEST_A.to_owned(),
        },
        evidence_digest_sha256: DIGEST_B.to_owned(),
        value: ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(BTreeSet::from([allowed_alternative])),
            required_values: None,
            preferred: None,
        },
    });

    let failure = resolve(input).unwrap_err();
    let report = failure.report.unwrap();
    let entry = report
        .entries
        .iter()
        .find(|entry| entry.family_id == "permission_rules")
        .unwrap();
    assert_eq!(entry.requested, Some(requested));
    assert!(entry.effective.is_none());
    assert!(matches!(
        entry.outcome,
        EntryOutcome::Rejected {
            reason: RejectionReason::ExternalConstraint {
                detail_code: "constraint_domain_violation",
                ..
            }
        }
    ));
    assert_code_parity(&report, "permission_rules", "rejected.external_constraint");
}

#[test]
fn operator_whole_list_authority_does_not_union_separate_allowed_alternatives() {
    let mut input = minimal_input();
    let family = families()
        .iter()
        .find(|family| family.id == "child_ceiling")
        .unwrap();
    let source = match family.activation.predicate {
        ActivationPredicate::Configured { sources } => {
            family
                .source
                .bindings
                .iter()
                .find(|binding| sources.contains(&binding.kind))
                .unwrap()
                .kind
        }
        _ => family.source.bindings[0].kind,
    };
    let capabilities = ResolutionValue::List {
        items: vec![
            ResolutionValue::Text {
                value: "fixture:a".to_owned(),
            },
            ResolutionValue::Text {
                value: "fixture:b".to_owned(),
            },
        ],
    };
    input.declared_values.push(DeclaredValue {
        family: family.id.to_owned(),
        source,
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: ResolutionValue::Object {
            fields: [
                (
                    "max_turns".to_owned(),
                    ResolutionValue::Integer { value: 1 },
                ),
                (
                    "max_wall_seconds".to_owned(),
                    ResolutionValue::Integer { value: 1 },
                ),
                (
                    "max_consecutive_errors".to_owned(),
                    ResolutionValue::Integer { value: 1 },
                ),
                ("capabilities".to_owned(), capabilities),
            ]
            .into_iter()
            .collect(),
        },
    });
    for (field, ceiling) in [
        ("max_turns", ExternalCeiling::ParentTurns),
        ("max_wall_seconds", ExternalCeiling::ParentWall),
    ] {
        input.constraint_evidence.push(ConstraintEvidence {
            family: family.id.to_owned(),
            field: field.to_owned(),
            ceiling,
            subject: constraint_subject(ceiling, input.runtime.selected_route.as_ref().unwrap()),
            evidence_digest_sha256: DIGEST_B.to_owned(),
            value: ConstraintValue::UpperBound {
                value: ResolutionValue::Integer { value: 1 },
            },
        });
    }
    input.constraint_evidence.push(ConstraintEvidence {
        family: family.id.to_owned(),
        field: "capabilities".to_owned(),
        ceiling: ExternalCeiling::OperatorAuthority,
        subject: EvidenceSubject::Operator {
            authority_digest_sha256: DIGEST_A.to_owned(),
        },
        evidence_digest_sha256: DIGEST_B.to_owned(),
        value: ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(BTreeSet::from([
                ResolutionValue::List {
                    items: vec![ResolutionValue::Text {
                        value: "fixture:a".to_owned(),
                    }],
                },
                ResolutionValue::List {
                    items: vec![ResolutionValue::Text {
                        value: "fixture:b".to_owned(),
                    }],
                },
            ])),
            required_values: None,
            preferred: None,
        },
    });

    let failure = resolve(input).unwrap_err();
    let report = failure.report.unwrap();
    let entry = &report.entries[usize::from(family.ordinal - 1)];
    assert!(matches!(
        entry.outcome,
        EntryOutcome::Rejected {
            reason: RejectionReason::ExternalConstraint {
                detail_code: "constraint_domain_violation",
                ..
            }
        }
    ));
}

#[test]
fn later_provider_degrade_cannot_undo_an_earlier_context_ceiling() {
    let family = families()
        .iter()
        .find(|family| family.id == "multimodal_token_budget")
        .unwrap();
    let source = match family.activation.predicate {
        ActivationPredicate::Configured { sources } => {
            family
                .source
                .bindings
                .iter()
                .find(|binding| sources.contains(&binding.kind))
                .unwrap()
                .kind
        }
        _ => family.source.bindings[0].kind,
    };
    let mut input = minimal_input();
    input.declared_values.push(DeclaredValue {
        family: family.id.to_owned(),
        source,
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: ResolutionValue::Integer { value: 30 },
    });
    let route = input.runtime.selected_route.clone().unwrap();
    input.constraint_evidence.extend([
        ConstraintEvidence {
            family: family.id.to_owned(),
            field: "$".to_owned(),
            ceiling: ExternalCeiling::ContextWindow,
            subject: EvidenceSubject::Route {
                route: route.clone(),
            },
            evidence_digest_sha256: DIGEST_A.to_owned(),
            value: ConstraintValue::UpperBound {
                value: ResolutionValue::Integer { value: 10 },
            },
        },
        ConstraintEvidence {
            family: family.id.to_owned(),
            field: "$".to_owned(),
            ceiling: ExternalCeiling::ProviderCapability,
            subject: EvidenceSubject::Route { route },
            evidence_digest_sha256: DIGEST_B.to_owned(),
            value: ConstraintValue::Domain {
                minimum: None,
                maximum: None,
                allowed_values: Some(BTreeSet::from([ResolutionValue::Integer { value: 20 }])),
                required_values: None,
                preferred: Some(ResolutionValue::Integer { value: 20 }),
            },
        },
    ]);

    let failure = resolve(input).unwrap_err();
    let report = failure.report.unwrap();
    let entry = &report.entries[usize::from(family.ordinal - 1)];
    assert_eq!(
        entry.requested,
        Some(ResolutionValue::Integer { value: 30 })
    );
    assert!(entry.effective.is_none());
    assert!(
        matches!(
            entry.outcome,
            EntryOutcome::Rejected {
                reason: RejectionReason::ExternalConstraint {
                    detail_code: "constraint_adjustment_conflict",
                    ..
                }
            }
        ),
        "unexpected conflict outcome: {:?}",
        entry.outcome
    );

    let reverse = families()
        .iter()
        .find(|family| family.id == "request_output_cap")
        .unwrap();
    let reverse_source = match reverse.activation.predicate {
        ActivationPredicate::Configured { sources } => {
            reverse
                .source
                .bindings
                .iter()
                .find(|binding| sources.contains(&binding.kind))
                .unwrap()
                .kind
        }
        _ => reverse.source.bindings[0].kind,
    };
    for (allowed, should_succeed) in [
        (
            BTreeSet::from([ResolutionValue::Integer { value: 20 }]),
            false,
        ),
        (
            BTreeSet::from([
                ResolutionValue::Integer { value: 10 },
                ResolutionValue::Integer { value: 20 },
            ]),
            true,
        ),
    ] {
        let mut input = minimal_input();
        input.declared_values.push(DeclaredValue {
            family: reverse.id.to_owned(),
            source: reverse_source,
            evidence_digest_sha256: DIGEST_A.to_owned(),
            value: ResolutionValue::Integer { value: 30 },
        });
        let route = input.runtime.selected_route.clone().unwrap();
        input.constraint_evidence.extend([
            ConstraintEvidence {
                family: reverse.id.to_owned(),
                field: "$".to_owned(),
                ceiling: ExternalCeiling::ProviderCapability,
                subject: EvidenceSubject::Route {
                    route: route.clone(),
                },
                evidence_digest_sha256: DIGEST_A.to_owned(),
                value: ConstraintValue::Domain {
                    minimum: None,
                    maximum: None,
                    allowed_values: Some(allowed),
                    required_values: None,
                    preferred: Some(ResolutionValue::Integer { value: 20 }),
                },
            },
            ConstraintEvidence {
                family: reverse.id.to_owned(),
                field: "$".to_owned(),
                ceiling: ExternalCeiling::ParentTokens,
                subject: constraint_subject(ExternalCeiling::ParentTokens, &route),
                evidence_digest_sha256: DIGEST_B.to_owned(),
                value: ConstraintValue::UpperBound {
                    value: ResolutionValue::Integer { value: 10 },
                },
            },
        ]);
        let failure = resolve(input).unwrap_err();
        let report = failure.report.unwrap();
        let entry = &report.entries[usize::from(reverse.ordinal - 1)];
        if should_succeed {
            assert_eq!(
                entry.effective,
                Some(ResolutionValue::Integer { value: 10 })
            );
            assert!(matches!(entry.outcome, EntryOutcome::Effective));
            assert_eq!(entry.adjustments.len(), 2);
        } else {
            assert!(entry.effective.is_none());
            assert!(matches!(
                entry.outcome,
                EntryOutcome::Rejected {
                    reason: RejectionReason::ExternalConstraint {
                        detail_code: "constraint_adjustment_conflict",
                        ..
                    }
                }
            ));
        }
    }
}

#[test]
fn catalog_reference_requires_and_accepts_whole_catalog_attestation() {
    let family = families()
        .iter()
        .find(|family| family.id == "builtin_prompt_corpus")
        .unwrap();
    let source = match family.activation.predicate {
        ActivationPredicate::Configured { sources } => {
            family
                .source
                .bindings
                .iter()
                .find(|binding| sources.contains(&binding.kind))
                .unwrap()
                .kind
        }
        _ => family.source.bindings[0].kind,
    };
    let requested = sample_schema(family.value_schema, family.ordinal);
    let mut missing = minimal_input();
    missing.declared_values.push(DeclaredValue {
        family: family.id.to_owned(),
        source,
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: requested.clone(),
    });
    let failure = resolve(missing.clone()).unwrap_err();
    let report = failure.report.unwrap();
    assert!(matches!(
        report.entries[usize::from(family.ordinal - 1)].outcome,
        EntryOutcome::Unresolved {
            reason: iteron_tunables::UnresolvedReason::ExternalConstraintMissing { .. }
        }
    ));

    missing.constraint_evidence.push(ConstraintEvidence {
        family: family.id.to_owned(),
        field: "max_render_bytes".to_owned(),
        ceiling: ExternalCeiling::ContextWindow,
        subject: EvidenceSubject::Route {
            route: missing.runtime.selected_route.clone().unwrap(),
        },
        evidence_digest_sha256: DIGEST_B.to_owned(),
        value: ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(BTreeSet::from([requested.clone()])),
            required_values: None,
            preferred: None,
        },
    });
    let failure = resolve(missing).unwrap_err();
    let report = failure.report.unwrap();
    let entry = &report.entries[usize::from(family.ordinal - 1)];
    assert_eq!(entry.requested, Some(requested.clone()));
    assert_eq!(entry.effective, Some(requested));
    assert!(matches!(entry.outcome, EntryOutcome::Effective));
}

#[test]
fn whole_catalog_evidence_is_exact_and_rejects_field_level_domain_forgery() {
    let builtin = families()
        .iter()
        .find(|family| family.id == "builtin_prompt_corpus")
        .unwrap();
    let mut allowed_mismatch = complete_success_input();
    let requested = allowed_mismatch
        .declared_values
        .iter()
        .find(|candidate| candidate.family == builtin.id)
        .unwrap()
        .value
        .clone();
    let mut mismatched_ref = requested.clone();
    let ResolutionValue::CatalogRef {
        digest_sha256,
        entry_count,
        ..
    } = &mut mismatched_ref
    else {
        panic!("builtin prompt corpus stopped using a catalog reference")
    };
    *digest_sha256 = DIGEST_B.to_owned();
    *entry_count = entry_count.saturating_add(1);
    let evidence = allowed_mismatch
        .constraint_evidence
        .iter_mut()
        .find(|evidence| {
            evidence.family == builtin.id
                && evidence.field == "max_render_bytes"
                && evidence.ceiling == ExternalCeiling::ContextWindow
        })
        .unwrap();
    evidence.value = ConstraintValue::Domain {
        minimum: None,
        maximum: None,
        allowed_values: Some(BTreeSet::from([mismatched_ref])),
        required_values: None,
        preferred: None,
    };
    let failure = resolve(allowed_mismatch).unwrap_err();
    let report = failure.report.unwrap();
    assert!(matches!(
        report.entries[usize::from(builtin.ordinal - 1)].outcome,
        EntryOutcome::Rejected {
            reason: RejectionReason::ExternalConstraint {
                detail_code: "constraint_domain_violation",
                ..
            }
        }
    ));

    let rate_card = families()
        .iter()
        .find(|family| family.id == "rate_card_catalog")
        .unwrap();
    let mut exact_mismatch = complete_success_input();
    let requested_rate_card = exact_mismatch
        .declared_values
        .iter()
        .find(|candidate| candidate.family == rate_card.id)
        .unwrap()
        .value
        .clone();
    let mut mismatched_rate_card = requested_rate_card;
    let ResolutionValue::CatalogRef { digest_sha256, .. } = &mut mismatched_rate_card else {
        panic!("rate card stopped using a catalog reference")
    };
    *digest_sha256 = DIGEST_B.to_owned();
    let evidence = exact_mismatch
        .constraint_evidence
        .iter_mut()
        .find(|evidence| {
            evidence.family == rate_card.id
                && evidence.field == "signature_sha256"
                && evidence.ceiling == ExternalCeiling::BenchmarkProtocol
        })
        .unwrap();
    evidence.value = ConstraintValue::Exact {
        value: mismatched_rate_card,
    };
    let failure = resolve(exact_mismatch).unwrap_err();
    let report = failure.report.unwrap();
    assert!(matches!(
        report.entries[usize::from(rate_card.ordinal - 1)].outcome,
        EntryOutcome::Rejected {
            reason: RejectionReason::ExternalConstraint {
                detail_code: "constraint_exact_mismatch",
                ..
            }
        }
    ));

    for forged in [
        ConstraintValue::Domain {
            minimum: Some(ResolutionValue::Integer { value: 1 }),
            maximum: None,
            allowed_values: None,
            required_values: None,
            preferred: None,
        },
        ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(BTreeSet::from([requested.clone()])),
            required_values: None,
            preferred: Some(ResolutionValue::Integer { value: 1 }),
        },
    ] {
        let mut input = complete_success_input();
        input
            .constraint_evidence
            .iter_mut()
            .find(|evidence| {
                evidence.family == builtin.id
                    && evidence.field == "max_render_bytes"
                    && evidence.ceiling == ExternalCeiling::ContextWindow
            })
            .unwrap()
            .value = forged;
        assert_invalid_input(input);
    }
}

#[test]
fn resolve_to_explain_distinguishes_literal_and_all_dynamic_fallback_evidence_states() {
    let literal = families()
        .iter()
        .find(|family| {
            family.implementation_status != ImplementationStatus::Missing
                && matches!(family.default.resolver, DefaultResolver::Literal)
                && !matches!(family.id, "provider" | "model")
                && family.default.value.is_some()
                && !matches!(
                    family.activation.predicate,
                    ActivationPredicate::Configured { .. }
                )
        })
        .unwrap();
    let dynamic = families()
        .iter()
        .find(|family| {
            family.implementation_status != ImplementationStatus::Missing
                && matches!(
                    family.default.resolver,
                    DefaultResolver::ModelMetadata { .. }
                )
                && !matches!(family.id, "provider" | "model")
                && family.default.value.is_some()
                && !matches!(
                    family.activation.predicate,
                    ActivationPredicate::Configured { .. }
                )
        })
        .unwrap();

    let mut literal_input = complete_success_input();
    literal_input.profile = None;
    literal_input
        .declared_values
        .retain(|value| value.family != literal.id);
    literal_input
        .default_evidence
        .retain(|evidence| evidence.family != literal.id);
    // Dropping the declaration hands this family to its embedded literal, so the attestation has
    // to name that literal rather than the sample value that is no longer in play.
    if let Some(default) = literal.default.value {
        reattest_external_ceiling(&mut literal_input, literal.id, &owned_value(default));
    }
    let literal_result = resolve(literal_input).unwrap();
    let literal_entry = &literal_result.report().entries[usize::from(literal.ordinal - 1)];
    assert!(matches!(
        literal_entry.provenance,
        Some(ResolutionProvenance {
            source: ResolutionSource::Default {
                evidence_digest_sha256: None,
                subject: None,
                fallback: false,
                ..
            }
        })
    ));
    let literal_json: Value =
        serde_json::from_str(&explain_entry_json(literal_result.report(), literal.id).unwrap())
            .unwrap();
    assert_eq!(
        literal_json["entry"]["source_code"],
        "source.default.literal"
    );

    for (state, attested) in [
        (None, false),
        (
            Some(EvidenceState::Absent {
                code: "fixture:absent".to_owned(),
            }),
            true,
        ),
        (
            Some(EvidenceState::Unsupported {
                code: "fixture:unsupported".to_owned(),
            }),
            true,
        ),
    ] {
        let mut input = complete_success_input();
        input.profile = None;
        input
            .declared_values
            .retain(|value| value.family != dynamic.id);
        input
            .default_evidence
            .retain(|evidence| evidence.family != dynamic.id);
        if let Some(state) = state {
            input.default_evidence.push(DefaultEvidence {
                family: dynamic.id.to_owned(),
                resolver_id: resolver_id(dynamic.default.resolver),
                subject: EvidenceSubject::Route {
                    route: input.runtime.selected_route.clone().unwrap(),
                },
                evidence_digest_sha256: DIGEST_B.to_owned(),
                state,
            });
        }
        let resolved = resolve(input).unwrap();
        let entry = &resolved.report().entries[usize::from(dynamic.ordinal - 1)];
        let Some(ResolutionProvenance {
            source:
                ResolutionSource::Default {
                    evidence_digest_sha256,
                    subject,
                    fallback,
                    ..
                },
        }) = &entry.provenance
        else {
            panic!("dynamic fallback lost its default provenance")
        };
        assert!(*fallback);
        assert_eq!(evidence_digest_sha256.is_some(), attested);
        assert_eq!(subject.is_some(), attested);
        let explained: Value =
            serde_json::from_str(&explain_entry_json(resolved.report(), dynamic.id).unwrap())
                .unwrap();
        assert_eq!(explained["entry"]["source_code"], "source.default.fallback");
    }
}

#[test]
fn explain_is_deterministic_bounded_ordered_and_complete() {
    let report = synthetic_report();
    let first = explain_text(&report).unwrap();
    let second = explain_text(&report).unwrap();
    assert_eq!(first, second);
    assert!(first.len() <= 262_144);
    assert_eq!(first.lines().count(), 163);
    assert!(first.contains("001 provider "));
    assert!(first.contains("160 replay_divergence_detection_policy "));
    assert!(!first.contains("fixture-secret"));
    assert!(!first.contains("fixture-resolver-never-rendered"));

    let mut reordered = report.clone();
    reordered.entries.swap(0, 1);
    assert_eq!(
        explain_text(&reordered),
        Err(ExplainError::InvalidReportStructure)
    );
    reordered.entries.pop();
    assert_eq!(
        explain_text(&reordered),
        Err(ExplainError::ReportBoundExceeded)
    );
}

#[test]
fn selectors_cover_canonical_semantic_and_every_alias_without_ambiguity() {
    let report = synthetic_report();
    for family in families() {
        for selector in std::iter::once(family.id)
            .chain(std::iter::once(family.semantic_key))
            .chain(family.aliases.iter().copied())
        {
            let json: Value =
                serde_json::from_str(&explain_entry_json(&report, selector).unwrap()).unwrap();
            assert_eq!(json["entry"]["family_id"], family.id);
        }
    }
    assert_eq!(
        explain_entry_json(&report, "unknown"),
        Err(ExplainError::EntryNotFound)
    );
    assert_eq!(
        explain_entry_json(&report, "provider\nmodel"),
        Err(ExplainError::InvalidSelector)
    );
    assert_eq!(
        explain_entry_json(&report, &"x".repeat(257)),
        Err(ExplainError::InvalidSelector)
    );
}

#[test]
fn unavailable_and_inactive_human_json_reason_codes_are_identical() {
    let mut report = synthetic_report();

    // `EntryOutcome::Unavailable` is structurally valid only on a family the registry declares
    // `Missing` with an `Unavailable` activation, so it cannot be synthesised onto an implemented
    // family: the report validator rejects that, correctly. The registry currently declares no
    // `Missing` family, which makes the outcome unreachable rather than merely unused. Assert that
    // precondition instead of faking coverage, so restoring a `Missing` family turns this red and
    // its parity case has to come back with it.
    assert!(
        !families()
            .iter()
            .any(|family| family.implementation_status
                == iteron_tunables::ImplementationStatus::Missing),
        "a Missing family exists again: restore the `unavailable.not_implemented` parity case"
    );

    let inactive = families()
        .iter()
        .find(|family| {
            family.implementation_status != iteron_tunables::ImplementationStatus::Missing
                && family.activation.inactive_reason.is_some()
        })
        .unwrap();
    let entry = &mut report.entries[usize::from(inactive.ordinal - 1)];
    entry.effective = None;
    entry.outcome = EntryOutcome::Inactive {
        cause: InactiveCause::Activation {
            reason: inactive.activation.inactive_reason.unwrap(),
        },
    };
    let expected = match inactive.activation.inactive_reason.unwrap() {
        iteron_tunables::InactiveReason::ConfigurationAbsent => "inactive.configuration_absent",
        iteron_tunables::InactiveReason::GroupedOrIncompleteSeam => {
            "inactive.grouped_or_incomplete_seam"
        }
        iteron_tunables::InactiveReason::NotImplemented => "inactive.not_implemented",
    };
    assert_code_parity(&report, inactive.id, expected);
}

#[test]
fn explain_redacts_values_and_all_input_control_plane_identifiers() {
    let mut report = synthetic_report();
    let family = families()
        .iter()
        .find(|family| {
            family
                .source
                .bindings
                .iter()
                .any(|binding| binding.kind == SourceKind::UserConfig)
                && matches!(
                    family.value_schema.domain,
                    StructuredValueDomain::Scalar {
                        domain: ScalarDomain::Text { .. }
                            | ScalarDomain::Enum {
                                catalog_id: Some(_),
                                ..
                            }
                    }
                )
        })
        .unwrap();
    let binding = family
        .source
        .bindings
        .iter()
        .find(|binding| binding.kind == SourceKind::UserConfig)
        .unwrap();
    let entry = &mut report.entries[usize::from(family.ordinal - 1)];
    let secret = match family.value_schema.domain {
        StructuredValueDomain::Scalar {
            domain: ScalarDomain::Text { .. },
        } => ResolutionValue::Text {
            value: "fixture-profile-secret".to_owned(),
        },
        StructuredValueDomain::Scalar {
            domain:
                ScalarDomain::Enum {
                    catalog_id: Some(_),
                    ..
                },
        } => ResolutionValue::Enum {
            value: "fixture:profile-secret".to_owned(),
        },
        _ => unreachable!("the selector admits only open text-like scalar families"),
    };
    entry.requested = Some(secret.clone());
    entry.effective = Some(secret.clone());
    entry.provenance = Some(ResolutionProvenance {
        source: ResolutionSource::Declared {
            kind: binding.kind,
            trust: binding.trust,
            declared_locator: binding.locator,
            evidence_digest_sha256: DIGEST_B.to_owned(),
        },
    });
    report.profile_digest_sha256 = Some(DIGEST_A.to_owned());
    entry.shadowed.push(ShadowedValue {
        value: secret,
        provenance: ResolutionProvenance {
            source: ResolutionSource::Profile {
                kind: binding.kind,
                trust: binding.trust,
                declared_locator: binding.locator,
                profile_digest_sha256: DIGEST_A.to_owned(),
            },
        },
        reason_code: "same_source_profile_overridden",
    });

    let text = explain_text(&report).unwrap();
    let json = explain_entry_json(&report, family.id).unwrap();
    for forbidden in [
        "fixture-secret",
        "profile-secret",
        "fixture-resolver-never-rendered",
    ] {
        assert!(!text.contains(forbidden));
        assert!(!json.contains(forbidden));
    }
    let json: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["entry"]["requested"]["redacted"], true);
    assert_eq!(
        json["entry"]["shadowed"][0]["reason_code"],
        "same_source_profile_overridden"
    );
    assert_eq!(json["entry"]["source_code"], "source.declared.user_config");
}

#[test]
fn forged_metadata_shadow_codes_and_aggregate_bounds_fail_closed() {
    let mut metadata = synthetic_report();
    metadata.entries[0].strategy_slots = &[];
    assert_eq!(
        explain_text(&metadata),
        Err(ExplainError::InvalidReportStructure)
    );

    let mut wrong_shape = synthetic_report();
    wrong_shape.entries[0].requested = Some(ResolutionValue::Boolean { value: false });
    wrong_shape.entries[0].effective = Some(ResolutionValue::Boolean { value: false });
    assert_eq!(
        explain_text(&wrong_shape),
        Err(ExplainError::InvalidReportStructure)
    );

    let mut text_enum_interchange = synthetic_report();
    let ResolutionValue::Enum { value } =
        text_enum_interchange.entries[0].requested.clone().unwrap()
    else {
        panic!("provider fixture stopped being an enum")
    };
    let forged_text = ResolutionValue::Text { value };
    text_enum_interchange.entries[0].requested = Some(forged_text.clone());
    text_enum_interchange.entries[0].effective = Some(forged_text);
    assert_eq!(
        explain_text(&text_enum_interchange),
        Err(ExplainError::InvalidReportStructure)
    );

    let mut out_of_range = synthetic_report();
    let max_turns = families()
        .iter()
        .find(|family| family.id == "max_turns")
        .unwrap();
    let forged_count = ResolutionValue::Integer { value: 1_000_001 };
    let entry = &mut out_of_range.entries[usize::from(max_turns.ordinal - 1)];
    entry.requested = Some(forged_count.clone());
    entry.effective = Some(forged_count);
    assert_eq!(
        explain_text(&out_of_range),
        Err(ExplainError::InvalidReportStructure)
    );

    let mut excessive_depth = synthetic_report();
    let mut nested = ResolutionValue::Boolean { value: false };
    for _ in 0..34 {
        nested = ResolutionValue::List {
            items: vec![nested],
        };
    }
    excessive_depth.entries[0].requested = Some(nested.clone());
    excessive_depth.entries[0].effective = Some(nested);
    assert_eq!(
        explain_text(&excessive_depth),
        Err(ExplainError::InvalidReportStructure)
    );

    let mut unused_catalog_schema = synthetic_report();
    let family = families()
        .iter()
        .find(|family| family.id == "model_fallback_chain")
        .unwrap();
    let entry = &mut unused_catalog_schema.entries[usize::from(family.ordinal - 1)];
    entry.requested = None;
    entry.effective = None;
    entry.provenance = None;
    entry.outcome = EntryOutcome::Unresolved {
        reason: iteron_tunables::UnresolvedReason::ResolverEvidenceMissing {
            resolver_id: resolver_id(family.default.resolver),
        },
    };
    assert_eq!(
        explain_text(&unused_catalog_schema),
        Err(ExplainError::InvalidReportStructure)
    );

    let mut shadow_code = synthetic_report();
    let provenance = shadow_code.entries[0].provenance.clone().unwrap();
    let shadow_value = shadow_code.entries[0].requested.clone().unwrap();
    shadow_code.entries[0].shadowed.push(ShadowedValue {
        value: shadow_value,
        provenance,
        reason_code: "caller_chosen_reason",
    });
    assert_eq!(
        explain_text(&shadow_code),
        Err(ExplainError::InvalidReportStructure)
    );

    let mut aggregate = synthetic_report();
    let provenance = aggregate.entries[0].provenance.clone().unwrap();
    let shadow_value = aggregate.entries[0].requested.clone().unwrap();
    aggregate.entries[0].shadowed = (0..354)
        .map(|_| ShadowedValue {
            value: shadow_value.clone(),
            provenance: provenance.clone(),
            reason_code: "lower_precedence",
        })
        .collect();
    assert_eq!(
        explain_text(&aggregate),
        Err(ExplainError::ReportBoundExceeded)
    );
}

#[test]
fn direct_value_beats_same_binding_profile_and_registry_order_beats_vector_order() {
    let mut input = minimal_input();
    input.profile = Some(ResolutionProfile {
        schema_version: RESOLUTION_SCHEMA_VERSION,
        profile_id: "fixture-profile".to_owned(),
        registry_revision: REGISTRY_REVISION,
        registry_digest: REGISTRY_DIGEST_SHA256.to_owned(),
        values: vec![ProfileValue {
            family: "max_turns".to_owned(),
            as_declared_source: SourceKind::UserConfig,
            value: ResolutionValue::Integer { value: 200 },
        }],
    });
    let user = DeclaredValue {
        family: "max_turns".to_owned(),
        source: SourceKind::UserConfig,
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: ResolutionValue::Integer { value: 100 },
    };
    let project = DeclaredValue {
        family: "max_turns".to_owned(),
        source: SourceKind::ProjectConfig,
        evidence_digest_sha256: DIGEST_B.to_owned(),
        value: ResolutionValue::Integer { value: 300 },
    };
    input.declared_values = vec![project.clone(), user.clone()];
    input.constraint_evidence.push(ConstraintEvidence {
        family: "max_turns".to_owned(),
        field: "$".to_owned(),
        ceiling: ExternalCeiling::ParentTurns,
        subject: EvidenceSubject::RuntimeSeam {
            seam: "parent_turns".to_owned(),
            subject_digest_sha256: DIGEST_A.to_owned(),
        },
        evidence_digest_sha256: DIGEST_B.to_owned(),
        value: ConstraintValue::UpperBound {
            value: ResolutionValue::Integer { value: 50 },
        },
    });
    let first = resolve(input.clone()).unwrap_err();
    input.declared_values = vec![user, project];
    let second = resolve(input).unwrap_err();
    assert_eq!(
        first, second,
        "semantic vector order must not affect digests"
    );

    let report = first.report.unwrap();
    let entry = &report.entries[4];
    assert_eq!(entry.family_id, "max_turns");
    assert_eq!(
        entry.requested,
        Some(ResolutionValue::Integer { value: 100 })
    );
    assert_eq!(
        entry.effective,
        Some(ResolutionValue::Integer { value: 50 })
    );
    assert!(matches!(
        entry.provenance.as_ref().map(|value| &value.source),
        Some(ResolutionSource::Declared {
            kind: SourceKind::UserConfig,
            ..
        })
    ));
    assert_eq!(entry.shadowed.len(), 2);
    assert_eq!(
        entry.shadowed[0].reason_code,
        "same_source_profile_overridden"
    );
    assert_eq!(entry.shadowed[1].reason_code, "project_tightening_inert");
    assert_eq!(entry.adjustments.len(), 1);
    assert_eq!(
        entry.adjustments[0].policy_id,
        "iteron://tunables/adjustments/clamp-numeric-v1"
    );
}

fn report_even_when_other_active_families_are_unresolved(
    input: ResolutionInput,
) -> ResolutionReport {
    match resolve(input) {
        Ok(resolved) => resolved.into_report(),
        Err(failure) => failure
            .report
            .expect("valid input carries an atomic failure report"),
    }
}

fn upper_bound(
    family: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> ConstraintEvidence {
    ConstraintEvidence {
        family: family.to_owned(),
        field: "$".to_owned(),
        ceiling,
        subject: constraint_subject(ceiling, &minimal_input().runtime.selected_route.unwrap()),
        evidence_digest_sha256: DIGEST_B.to_owned(),
        value: ConstraintValue::UpperBound { value },
    }
}

#[test]
fn project_numeric_sources_only_lower_operator_or_canonical_ceilings() {
    let cases = [
        (100, 50, 50, SourceKind::ProjectConfig, "project_tightened"),
        (
            50,
            100,
            50,
            SourceKind::UserConfig,
            "project_tightening_inert",
        ),
    ];
    for (operator, project, expected, expected_source, shadow_reason) in cases {
        let mut input = minimal_input();
        input.declared_values = vec![
            DeclaredValue {
                family: "max_turns".to_owned(),
                source: SourceKind::UserConfig,
                evidence_digest_sha256: DIGEST_A.to_owned(),
                value: ResolutionValue::Integer { value: operator },
            },
            DeclaredValue {
                family: "max_turns".to_owned(),
                source: SourceKind::ProjectConfig,
                evidence_digest_sha256: DIGEST_B.to_owned(),
                value: ResolutionValue::Integer { value: project },
            },
        ];
        input.constraint_evidence.push(upper_bound(
            "max_turns",
            ExternalCeiling::ParentTurns,
            ResolutionValue::Integer { value: 1_000 },
        ));
        let report = report_even_when_other_active_families_are_unresolved(input);
        let entry = &report.entries[4];
        assert_eq!(
            entry.requested,
            Some(ResolutionValue::Integer { value: expected })
        );
        assert!(matches!(
            entry.provenance.as_ref().map(|provenance| &provenance.source),
            Some(ResolutionSource::Declared { kind, .. }) if *kind == expected_source
        ));
        assert_eq!(entry.shadowed.last().unwrap().reason_code, shadow_reason);
    }

    let mut default_limited = minimal_input();
    default_limited.declared_values.push(DeclaredValue {
        family: "max_turns".to_owned(),
        source: SourceKind::ProjectConfig,
        evidence_digest_sha256: DIGEST_B.to_owned(),
        value: ResolutionValue::Integer { value: 900 },
    });
    default_limited.constraint_evidence.push(upper_bound(
        "max_turns",
        ExternalCeiling::ParentTurns,
        ResolutionValue::Integer { value: 1_000 },
    ));
    let report = report_even_when_other_active_families_are_unresolved(default_limited);
    let entry = &report.entries[4];
    assert_eq!(
        entry.requested,
        Some(ResolutionValue::Integer { value: 600 })
    );
    assert!(matches!(
        entry
            .provenance
            .as_ref()
            .map(|provenance| &provenance.source),
        Some(ResolutionSource::Default { .. })
    ));
    assert_eq!(
        entry.shadowed.last().unwrap().reason_code,
        "project_tightening_inert"
    );
}

#[test]
fn project_can_introduce_optional_cost_ceiling_and_revoke_but_not_grant_code() {
    let mut cost = minimal_input();
    cost.declared_values.push(DeclaredValue {
        family: "max_usd".to_owned(),
        source: SourceKind::ProjectConfig,
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: ResolutionValue::Decimal {
            value: iteron_tunables::DecimalValue {
                coefficient: 125,
                scale: 2,
            },
        },
    });
    cost.constraint_evidence.push(upper_bound(
        "max_usd",
        ExternalCeiling::ParentCost,
        ResolutionValue::Decimal {
            value: iteron_tunables::DecimalValue {
                coefficient: 2,
                scale: 0,
            },
        },
    ));
    let report = report_even_when_other_active_families_are_unresolved(cost);
    assert_eq!(
        report.entries[5].requested,
        Some(ResolutionValue::Decimal {
            value: iteron_tunables::DecimalValue {
                coefficient: 125,
                scale: 2,
            }
        })
    );

    for (project, expected, expected_source) in [
        (false, false, SourceKind::ProjectConfig),
        (true, true, SourceKind::Builtin),
    ] {
        let mut code = minimal_input();
        code.declared_values.push(DeclaredValue {
            family: "allow_code".to_owned(),
            source: SourceKind::ProjectConfig,
            evidence_digest_sha256: DIGEST_A.to_owned(),
            value: ResolutionValue::Boolean { value: project },
        });
        code.constraint_evidence.push(ConstraintEvidence {
            family: "allow_code".to_owned(),
            field: "$".to_owned(),
            ceiling: ExternalCeiling::OperatorAuthority,
            subject: EvidenceSubject::Operator {
                authority_digest_sha256: DIGEST_A.to_owned(),
            },
            evidence_digest_sha256: DIGEST_B.to_owned(),
            value: ConstraintValue::Domain {
                minimum: None,
                maximum: None,
                allowed_values: Some(BTreeSet::from([
                    ResolutionValue::Boolean { value: false },
                    ResolutionValue::Boolean { value: true },
                ])),
                required_values: None,
                preferred: None,
            },
        });
        let report = report_even_when_other_active_families_are_unresolved(code);
        let entry = &report.entries[8];
        assert_eq!(
            entry.requested,
            Some(ResolutionValue::Boolean { value: expected })
        );
        match entry
            .provenance
            .as_ref()
            .map(|provenance| &provenance.source)
        {
            Some(ResolutionSource::Declared { kind, .. }) => assert_eq!(*kind, expected_source),
            Some(ResolutionSource::Default { .. }) => {
                assert_eq!(expected_source, SourceKind::Builtin)
            }
            other => panic!("unexpected allow_code provenance: {other:?}"),
        }
    }
}

#[test]
fn project_model_is_only_a_route_suggestion_below_operator_sources() {
    let mut input = minimal_input();
    input.declared_values = vec![
        DeclaredValue {
            family: "model".to_owned(),
            source: SourceKind::UserConfig,
            evidence_digest_sha256: DIGEST_A.to_owned(),
            value: ResolutionValue::Enum {
                value: "glm-5.2".to_owned(),
            },
        },
        DeclaredValue {
            family: "model".to_owned(),
            source: SourceKind::ProjectConfig,
            evidence_digest_sha256: DIGEST_B.to_owned(),
            value: ResolutionValue::Enum {
                value: "glm".to_owned(),
            },
        },
    ];
    input.constraint_evidence.push(ConstraintEvidence {
        family: "model".to_owned(),
        field: "$".to_owned(),
        ceiling: ExternalCeiling::ProviderCapability,
        subject: EvidenceSubject::Route {
            route: input.runtime.selected_route.clone().unwrap(),
        },
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(BTreeSet::from([ResolutionValue::Enum {
                value: "glm-5.2".to_owned(),
            }])),
            required_values: None,
            preferred: None,
        },
    });
    let report = report_even_when_other_active_families_are_unresolved(input);
    let entry = &report.entries[1];
    assert!(matches!(
        entry
            .provenance
            .as_ref()
            .map(|provenance| &provenance.source),
        Some(ResolutionSource::Declared {
            kind: SourceKind::UserConfig,
            ..
        })
    ));
    assert_eq!(
        entry.shadowed.last().unwrap().reason_code,
        "lower_precedence"
    );
}

#[test]
fn aliases_canonicalize_before_duplicate_detection_and_shadowed_values_still_validate() {
    let mut duplicate = minimal_input();
    duplicate.declared_values = vec![
        DeclaredValue {
            family: "max_wall_secs".to_owned(),
            source: SourceKind::UserConfig,
            evidence_digest_sha256: DIGEST_A.to_owned(),
            value: ResolutionValue::Integer { value: 100 },
        },
        DeclaredValue {
            family: "wall_timeout".to_owned(),
            source: SourceKind::UserConfig,
            evidence_digest_sha256: DIGEST_B.to_owned(),
            value: ResolutionValue::Integer { value: 200 },
        },
    ];
    assert_invalid_input(duplicate);

    let mut invalid_shadow = minimal_input();
    invalid_shadow.declared_values = vec![
        DeclaredValue {
            family: "max_wall_secs".to_owned(),
            source: SourceKind::Cli,
            evidence_digest_sha256: DIGEST_A.to_owned(),
            value: ResolutionValue::Integer { value: 100 },
        },
        DeclaredValue {
            family: "max_wall_secs".to_owned(),
            source: SourceKind::ProjectConfig,
            evidence_digest_sha256: DIGEST_B.to_owned(),
            value: ResolutionValue::Text {
                value: "not-an-integer".to_owned(),
            },
        },
    ];
    assert_invalid_input(invalid_shadow);
}

#[test]
fn activation_default_route_and_constraint_evidence_fail_closed() {
    let mut unknown = minimal_input();
    unknown.activation_evidence.push(ActivationEvidence {
        family: "retry_backoff_base".to_owned(),
        seam: "crates/cli/src/config/retry.rs".to_owned(),
        subject_digest_sha256: DIGEST_A.to_owned(),
        evidence_digest_sha256: DIGEST_B.to_owned(),
        active: true,
    });
    assert_invalid_input(unknown);

    let mut default = minimal_input();
    let family = families()
        .iter()
        .find(|family| {
            matches!(family.default.resolver, DefaultResolver::Builtin { .. })
                && family.default.value.is_none()
        })
        .unwrap();
    let selected = default.runtime.selected_route.clone().unwrap();
    default.default_evidence.push(DefaultEvidence {
        family: family.id.to_owned(),
        resolver_id: resolver_id(family.default.resolver),
        subject: EvidenceSubject::Route { route: selected },
        evidence_digest_sha256: DIGEST_A.to_owned(),
        state: EvidenceState::Present {
            value: sample_value(family.value_schema.domain, family.ordinal),
        },
    });
    assert_invalid_input(default);

    let mut route = minimal_input();
    route
        .runtime
        .selected_route
        .as_mut()
        .unwrap()
        .route_revision = "unadmitted-v2".to_owned();
    assert_invalid_input(route);

    let mut constraint = minimal_input();
    constraint.constraint_evidence.push(ConstraintEvidence {
        family: "max_turns".to_owned(),
        field: "not_a_schema_field".to_owned(),
        ceiling: ExternalCeiling::ParentTurns,
        subject: EvidenceSubject::Global,
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: ConstraintValue::UpperBound {
            value: ResolutionValue::Integer { value: 40 },
        },
    });
    assert_invalid_input(constraint);

    let mut mixed_domain = minimal_input();
    mixed_domain.constraint_evidence.push(ConstraintEvidence {
        family: "bypass_permissions".to_owned(),
        field: "$".to_owned(),
        ceiling: ExternalCeiling::OperatorAuthority,
        subject: EvidenceSubject::Operator {
            authority_digest_sha256: DIGEST_A.to_owned(),
        },
        evidence_digest_sha256: DIGEST_B.to_owned(),
        value: ConstraintValue::Domain {
            minimum: Some(ResolutionValue::Boolean { value: false }),
            maximum: None,
            allowed_values: Some(BTreeSet::from([ResolutionValue::Boolean { value: true }])),
            required_values: None,
            preferred: None,
        },
    });
    assert_invalid_input(mixed_domain);
}

#[test]
fn empty_environment_snapshot_identity_is_schema_valid() {
    let family = families()
        .iter()
        .find(|family| family.id == "environment_snapshot")
        .unwrap();
    let source = match family.activation.predicate {
        ActivationPredicate::Configured { sources } => {
            family
                .source
                .bindings
                .iter()
                .find(|binding| sources.contains(&binding.kind))
                .unwrap()
                .kind
        }
        _ => family.source.bindings[0].kind,
    };
    let mut input = minimal_input();
    let requested = ResolutionValue::Object {
        fields: [
            (
                "present".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
            (
                "digest_sha256".to_owned(),
                ResolutionValue::Text {
                    value: DIGEST_A.to_owned(),
                },
            ),
            (
                "canonical_bytes".to_owned(),
                ResolutionValue::Integer { value: 0 },
            ),
            (
                "trust".to_owned(),
                ResolutionValue::Enum {
                    value: "workspace".to_owned(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    input.declared_values.push(DeclaredValue {
        family: family.id.to_owned(),
        source,
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: requested.clone(),
    });
    let failure = resolve(input).unwrap_err();
    assert_eq!(failure.code, FailureCode::ActiveResolutionFailed);
    let report = failure.report.unwrap();
    assert_eq!(
        report.entries[usize::from(family.ordinal - 1)].requested,
        Some(requested)
    );
}

#[test]
fn resolve_failure_is_atomic_deterministic_and_still_reports_all_160_families() {
    let first = resolve(minimal_input()).unwrap_err();
    let second = resolve(minimal_input()).unwrap_err();
    assert_eq!(first.code, FailureCode::ActiveResolutionFailed);
    assert_eq!(first, second);
    let report = first
        .report
        .expect("active failure retains the bounded audit report");
    assert_eq!(report.entries.len(), 160);
    // `Unavailable` is reported for exactly the families the registry declares `Missing`, and for
    // no others. Stated as a correspondence rather than as one pinned ordinal, this keeps holding
    // when families gain or lose a production seam.
    let unavailable: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| matches!(entry.outcome, EntryOutcome::Unavailable))
        .map(|entry| entry.family_id)
        .collect();
    let missing: Vec<_> = families()
        .iter()
        .filter(|family| {
            family.implementation_status == iteron_tunables::ImplementationStatus::Missing
        })
        .map(|family| family.id)
        .collect();
    assert_eq!(unavailable, missing);
    assert!(
        report
            .entries
            .iter()
            .any(|entry| matches!(entry.outcome, EntryOutcome::Inactive { .. }))
    );
    assert!(report.entries.iter().any(|entry| matches!(
        entry.outcome,
        EntryOutcome::Unresolved {
            reason: iteron_tunables::UnresolvedReason::ResolverEvidenceMissing { .. }
        }
    )));
    assert!(report.entries.iter().any(|entry| matches!(
        entry.outcome,
        EntryOutcome::Unresolved {
            reason: iteron_tunables::UnresolvedReason::ExternalConstraintMissing { .. }
        }
    )));
}

#[test]
fn resolver_failure_from_missing_scalar_catalogs_remains_explainable() {
    let mut input = minimal_input();
    input.runtime.catalogs.clear();
    let failure = resolve(input).unwrap_err();
    assert_eq!(failure.code, FailureCode::ActiveResolutionFailed);
    let report = failure.report.unwrap();
    assert!(matches!(
        report.entries[0].outcome,
        EntryOutcome::Unresolved {
            reason: iteron_tunables::UnresolvedReason::ResolverEvidenceMissing { .. }
        }
    ));
    assert!(explain_text(&report).is_ok());
    assert!(explain_entry_json(&report, "provider").is_ok());
}

#[test]
fn resolve_json_rejects_duplicate_nested_map_and_object_keys() {
    for kind in ["map", "object"] {
        let collection = if kind == "map" { "entries" } else { "fields" };
        let json = format!(
            r#"{{"schema_version":{RESOLUTION_SCHEMA_VERSION},"registry_id":"{REGISTRY_ID}","registry_revision":{REGISTRY_REVISION},"registry_digest":"{REGISTRY_DIGEST_SHA256}","declared_values":[{{"family":"permission_rules","source":"user_config","evidence_digest_sha256":"{DIGEST_A}","value":{{"type":"{kind}","{collection}":{{"duplicate":{{"type":"boolean","value":false}},"duplicate":{{"type":"boolean","value":true}}}}}}}}]}}"#
        );
        let failure = resolve_json(json.as_bytes()).unwrap_err();
        assert_eq!(failure.code, FailureCode::InvalidInput);
        assert!(failure.report.is_none());
    }
}

#[test]
fn provider_rejection_reason_has_stable_redacted_code() {
    let mut report = synthetic_report();
    let family = families()
        .iter()
        .find(|family| family.requirements.provider != iteron_tunables::ProviderRequirement::None)
        .unwrap();
    let entry = &mut report.entries[usize::from(family.ordinal - 1)];
    entry.effective = None;
    entry.outcome = EntryOutcome::Rejected {
        reason: RejectionReason::ProviderRequirement {
            requirement: family.requirements.provider,
            route: None,
            missing_capabilities: family.requirements.capabilities.to_vec(),
        },
    };
    assert_code_parity(&report, family.id, "rejected.provider_requirement");
}

#[test]
fn genuine_missing_selected_route_report_explains_exact_sorted_capabilities() {
    let family = families()
        .iter()
        .find(|family| family.id == "per_agent_model")
        .unwrap();
    let mut input = minimal_input();
    input.runtime.admitted_routes.clear();
    input.runtime.selected_route = None;
    input.runtime.catalogs = vec![catalog_snapshot(
        "iteron://tunables/catalogs/model-routes-v1",
        "fixture:route",
    )];
    input.declared_values = vec![DeclaredValue {
        family: family.id.to_owned(),
        source: SourceKind::DerivedPolicy,
        evidence_digest_sha256: DIGEST_A.to_owned(),
        value: ResolutionValue::Enum {
            value: "fixture:route".to_owned(),
        },
    }];

    let failure = resolve(input).unwrap_err();
    assert_eq!(failure.code, FailureCode::ActiveResolutionFailed);
    let report = failure.report.unwrap();
    let entry = &report.entries[usize::from(family.ordinal - 1)];
    let RejectionReason::ProviderRequirement {
        route,
        missing_capabilities,
        ..
    } = (match &entry.outcome {
        EntryOutcome::Rejected { reason } => reason,
        outcome => panic!("expected provider rejection, got {outcome:?}"),
    })
    else {
        panic!("expected provider-requirement rejection")
    };
    let mut expected = family.requirements.capabilities.to_vec();
    expected.sort_unstable();
    expected.dedup();
    assert!(route.is_none());
    assert_eq!(missing_capabilities, &expected);

    let explained: Value =
        serde_json::from_str(&explain_entry_json(&report, family.id).unwrap()).unwrap();
    assert_eq!(
        explained["entry"]["reason_code"],
        "rejected.provider_requirement"
    );
    assert!(!explained.to_string().contains("fixture:route"));
}

fn assert_code_parity(report: &ResolutionReport, selector: &str, expected: &str) {
    let json: Value = serde_json::from_str(&explain_entry_json(report, selector).unwrap()).unwrap();
    assert_eq!(json["entry"]["reason_code"], expected);
    let text = explain_text(report).unwrap();
    let line = text
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(selector))
        .unwrap();
    assert!(line.contains(&format!("code={expected}")));
}

fn assert_invalid_input(input: ResolutionInput) {
    let failure = resolve(input).unwrap_err();
    assert_eq!(failure.code, FailureCode::InvalidInput);
    assert!(failure.report.is_none());
}
