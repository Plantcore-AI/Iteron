use core_protocol::{
    Block, Budget, CostAttribution, CostProjection, CostProjectionIdentity,
    DurableEnvironmentContext, DurableInstructionContext, Event, EventKind, ImageContent, Message,
    Op, PermissionRules, PricingRoute, ProviderState, RateCard, SignedRateCard, TokenRateCard,
    ToolResult, ToolUse, Usage, WorkflowCostEvidence, WorkflowEvent, WorkflowMetrics,
    WorkflowTaskEvidence,
};
use core_record::replay;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
static TEMP_ID: AtomicU64 = AtomicU64::new(0);
const MAX_CONTRACT_BYTES: u64 = 1024 * 1024;
const MAX_FIXTURE_BYTES: u64 = 1024 * 1024;
const MAX_FIXTURE_OBJECTS: usize = 4096;

const WRITABLE_EVENT_TAGS: [&str; 32] = [
    "approval",
    "artifact_produced",
    "checkpoint",
    "compaction",
    "context_injection",
    "cost_projected",
    "done",
    "effect_done",
    "effect_failed",
    "effect_intent",
    "effect_unknown",
    "effort_changed",
    "message",
    "model_selected",
    "notice",
    "phase",
    "policy_changed",
    "rate_card_bound",
    "run_start",
    "subagent_finished",
    "subagent_finished_v2",
    "subagent_spawned",
    "submission_rejected",
    "text",
    "thinking",
    "tool_done",
    "tool_ready",
    "turn_end",
    "turn_start",
    "usd_ceiling_changed",
    "workflow",
    "workflow_v2",
];

const BLOCK_TAGS: [&str; 5] = [
    "provider_state",
    "text",
    "thinking",
    "tool_result",
    "tool_use",
];

const WORKFLOW_EVENT_TAGS: [&str; 7] = [
    "child_finished",
    "child_started",
    "finished",
    "phase_changed",
    "planned",
    "reduced",
    "started",
];

const COST_ATTRIBUTION_TAGS: [&str; 2] = ["direct_subagent", "workflow_child"];

// `ArtifactRef` and its `Provenance` became durable with `artifact_produced` (#78):
// making a type reachable from the record makes its shape a published surface.
const NAMED_SURFACE_IDS: [&str; 21] = [
    "record.named.artifact-ref",
    "record.named.budget",
    "record.named.cost-projection",
    "record.named.cost-projection-identity",
    "record.named.durable-environment-context",
    "record.named.durable-instruction-context",
    "record.named.image-content",
    "record.named.message",
    "record.named.permission-rules",
    "record.named.pricing-route",
    "record.named.provenance",
    "record.named.provider-state",
    "record.named.rate-card",
    "record.named.signed-rate-card",
    "record.named.token-rate-card",
    "record.named.tool-result",
    "record.named.tool-use",
    "record.named.usage",
    "record.named.workflow-cost-evidence",
    "record.named.workflow-metrics",
    "record.named.workflow-task-evidence",
];

type NamedWires = BTreeMap<&'static str, BTreeSet<String>>;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root exists")
}

#[derive(Deserialize)]
struct CompatibilityContract {
    surfaces: Vec<CompatibilitySurface>,
}

#[derive(Deserialize)]
struct CompatibilitySurface {
    id: String,
    current_version: u32,
    version_field: Option<String>,
    #[serde(default)]
    selector: Option<FixtureSelector>,
    fixtures: Vec<CompatibilityFixture>,
    fields: Vec<CompatibilityField>,
    #[serde(default)]
    compatibility_shims: Vec<CompatibilityShim>,
}

#[derive(Deserialize)]
struct CompatibilityField {
    name: String,
}

#[derive(Deserialize)]
struct FixtureSelector {
    field: String,
    value: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FixtureFormat {
    Json,
    Jsonl,
}

#[derive(Deserialize)]
struct CompatibilityFixture {
    path: String,
    format: FixtureFormat,
    schema_version: u32,
}

#[derive(Deserialize)]
struct CompatibilityShim {
    old_field: String,
    replacement: Option<String>,
    target_version: u32,
    fixtures: Vec<String>,
}

fn read_bounded(path: &Path, max: u64) -> Vec<u8> {
    let metadata = std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", path.display()));
    assert!(
        metadata.len() <= max,
        "{} exceeds the {max}-byte compatibility-test bound",
        path.display()
    );
    std::fs::read(path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn compatibility_contract(root: &Path) -> CompatibilityContract {
    let path = root.join("governance/schema-compatibility.json");
    serde_json::from_slice(&read_bounded(&path, MAX_CONTRACT_BYTES)).unwrap_or_else(|error| {
        panic!("invalid compatibility contract {}: {error}", path.display())
    })
}

fn fixture_values(root: &Path, fixture: &CompatibilityFixture) -> Vec<Value> {
    let path = root.join(&fixture.path);
    let bytes = read_bounded(&path, MAX_FIXTURE_BYTES);
    let values = match fixture.format {
        FixtureFormat::Json => vec![
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("invalid JSON fixture {}: {error}", path.display())),
        ],
        FixtureFormat::Jsonl => std::str::from_utf8(&bytes)
            .unwrap_or_else(|error| panic!("non-UTF-8 JSONL fixture {}: {error}", path.display()))
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!("invalid JSONL fixture {}: {error}", path.display())
                })
            })
            .collect(),
    };
    assert!(
        !values.is_empty() && values.len() <= MAX_FIXTURE_OBJECTS,
        "{} must contain 1..={MAX_FIXTURE_OBJECTS} objects",
        path.display()
    );
    assert!(
        values.iter().all(Value::is_object),
        "{} must contain only top-level objects",
        path.display()
    );
    values
}

fn selected_fixture_values(
    root: &Path,
    surface: &CompatibilitySurface,
    fixture: &CompatibilityFixture,
) -> Vec<Value> {
    let values = fixture_values(root, fixture);
    let Some(selector) = &surface.selector else {
        return values;
    };
    let selected = values
        .into_iter()
        .filter(|value| value.get(&selector.field).and_then(Value::as_str) == Some(&selector.value))
        .collect::<Vec<_>>();
    assert!(
        !selected.is_empty(),
        "{} has no record for {}={}",
        fixture.path,
        selector.field,
        selector.value
    );
    selected
}

fn typed_roundtrip<T>(raw: &Value, label: &str) -> (T, Value)
where
    T: DeserializeOwned + Serialize,
{
    let typed: T = serde_json::from_value(raw.clone())
        .unwrap_or_else(|error| panic!("{label} failed typed decode: {error}"));
    let encoded = serde_json::to_value(&typed)
        .unwrap_or_else(|error| panic!("{label} failed typed serialization: {error}"));
    let reparsed: T = serde_json::from_value(encoded.clone())
        .unwrap_or_else(|error| panic!("{label} failed stable typed decode: {error}"));
    assert_eq!(
        serde_json::to_value(reparsed).unwrap(),
        encoded,
        "{label} typed serialization is not stable"
    );
    (typed, encoded)
}

fn canonical_current_projection(
    raw: &Value,
    surface: &CompatibilitySurface,
    fixture: &CompatibilityFixture,
    label: &str,
) -> serde_json::Map<String, Value> {
    let raw = raw
        .as_object()
        .unwrap_or_else(|| panic!("{label} is not an object"));
    let mut canonical = raw.clone();
    let mut shims = surface.compatibility_shims.iter().collect::<Vec<_>>();
    shims.sort_by(|left, right| {
        (left.target_version, left.old_field.as_str())
            .cmp(&(right.target_version, right.old_field.as_str()))
    });
    for shim in shims {
        let Some(old) = canonical.remove(&shim.old_field) else {
            continue;
        };
        if raw.contains_key(&shim.old_field) {
            assert!(
                shim.fixtures.contains(&fixture.path),
                "{label} uses `{}` without declaring the fixture on its shim",
                shim.old_field
            );
        }
        if let Some(replacement) = &shim.replacement {
            assert!(
                !canonical.contains_key(replacement),
                "{label} migration would overwrite replacement field `{replacement}`"
            );
            canonical.insert(replacement.clone(), old);
        }
        if let Some(version_field) = &surface.version_field {
            canonical.insert(version_field.clone(), Value::from(shim.target_version));
        }
    }
    if let Some(version_field) = &surface.version_field {
        canonical.insert(version_field.clone(), Value::from(surface.current_version));
    }
    canonical
}

fn assert_recursive_projection_preserves(
    original: &Value,
    projected: &Value,
    label: &str,
    path: &str,
) {
    match original {
        Value::Object(original) => {
            let projected = projected.as_object().unwrap_or_else(|| {
                panic!("{label} changed object `{path}` into a non-object: {projected}")
            });
            for (field, original_value) in original {
                let projected_value = projected.get(field).unwrap_or_else(|| {
                    panic!("{label} dropped physical payload field `{path}.{field}`")
                });
                assert_recursive_projection_preserves(
                    original_value,
                    projected_value,
                    label,
                    &format!("{path}.{field}"),
                );
            }
        }
        Value::Array(original) => {
            let projected = projected.as_array().unwrap_or_else(|| {
                panic!("{label} changed array `{path}` into a non-array: {projected}")
            });
            assert_eq!(
                projected.len(),
                original.len(),
                "{label} changed the physical payload array length at `{path}`"
            );
            for (index, (original_value, projected_value)) in
                original.iter().zip(projected).enumerate()
            {
                assert_recursive_projection_preserves(
                    original_value,
                    projected_value,
                    label,
                    &format!("{path}[{index}]"),
                );
            }
        }
        _ => assert_eq!(
            projected, original,
            "{label} changed the physical payload value at `{path}`"
        ),
    }
}

fn typed_stable<T>(
    raw: &Value,
    surface: &CompatibilitySurface,
    fixture: &CompatibilityFixture,
    label: &str,
) -> (T, Value)
where
    T: DeserializeOwned + Serialize,
{
    let (typed, encoded) = typed_roundtrip::<T>(raw, label);
    let canonical = canonical_current_projection(raw, surface, fixture, label);
    let active_fields = surface
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<BTreeSet<_>>();
    let canonical_fields = canonical
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert!(
        canonical_fields.is_subset(&active_fields),
        "{label} canonical migration retained stale or undeclared fields: {canonical_fields:?} vs {active_fields:?}"
    );
    let encoded_object = encoded
        .as_object()
        .unwrap_or_else(|| panic!("{label} typed encoding is not an object"));
    let encoded_fields = encoded_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert!(
        encoded_fields.is_subset(&active_fields),
        "{label} typed encoding emitted undeclared current fields: {encoded_fields:?} vs {active_fields:?}"
    );
    for (field, value) in canonical {
        assert_eq!(
            encoded_object.get(&field),
            Some(&value),
            "{label} typed current serialization changed traceable field `{field}`"
        );
    }
    if fixture.schema_version == surface.current_version {
        assert_eq!(encoded, *raw, "{label} current-version wire shape changed");
    }
    (typed, encoded)
}

fn typed_surface_wires<T>(
    root: &Path,
    contract: &CompatibilityContract,
    prefix: &str,
    selector_field: &str,
) -> BTreeSet<String>
where
    T: DeserializeOwned + Serialize,
{
    let surfaces = contract
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with(prefix))
        .collect::<Vec<_>>();
    assert!(!surfaces.is_empty(), "{prefix} surfaces are declared");
    let mut wires = BTreeSet::new();
    for surface in surfaces {
        let tag = surface
            .id
            .strip_prefix(prefix)
            .expect("filtered surface retains its prefix");
        let selector = surface
            .selector
            .as_ref()
            .unwrap_or_else(|| panic!("{} lacks a selector", surface.id));
        assert_eq!(
            selector.field, selector_field,
            "{} selector field",
            surface.id
        );
        assert_eq!(selector.value, tag, "{} selector value", surface.id);
        for fixture in &surface.fixtures {
            for (index, raw) in selected_fixture_values(root, surface, fixture)
                .into_iter()
                .enumerate()
            {
                let label = format!(
                    "{} fixture {} schema {} object {}",
                    surface.id,
                    fixture.path,
                    fixture.schema_version,
                    index + 1
                );
                let (_, encoded) = typed_stable::<T>(&raw, surface, fixture, &label);
                wires.insert(serde_json::to_string(&encoded).unwrap());
            }
        }
    }
    wires
}

fn canonical_wire<T: Serialize>(value: &T) -> String {
    serde_json::to_string(&serde_json::to_value(value).expect("named value serializes"))
        .expect("canonical named value serializes")
}

fn record_named<T: Serialize>(wires: &mut NamedWires, surface_id: &'static str, value: &T) {
    wires
        .entry(surface_id)
        .or_default()
        .insert(canonical_wire(value));
}

fn typed_named_fixture_wires<T>(root: &Path, surface: &CompatibilitySurface) -> BTreeSet<String>
where
    T: DeserializeOwned + Serialize,
{
    assert!(
        surface.selector.is_none(),
        "{} must be a direct object surface",
        surface.id
    );
    assert!(
        surface.version_field.is_none(),
        "{} is nested and versionless",
        surface.id
    );
    assert!(
        surface.compatibility_shims.is_empty(),
        "{} cannot use local shims without a nested version field; breaking evolution requires a new enclosing event tag",
        surface.id
    );
    let mut wires = BTreeSet::new();
    for fixture in &surface.fixtures {
        for (index, raw) in selected_fixture_values(root, surface, fixture)
            .into_iter()
            .enumerate()
        {
            let label = format!(
                "{} fixture {} schema {} object {}",
                surface.id,
                fixture.path,
                fixture.schema_version,
                index + 1
            );
            let (_, encoded) = typed_stable::<T>(&raw, surface, fixture, &label);
            wires.insert(serde_json::to_string(&encoded).unwrap());
        }
    }
    assert!(
        !wires.is_empty(),
        "{} has direct fixture values",
        surface.id
    );
    wires
}

fn assert_named_surface_corpus(
    root: &Path,
    contract: &CompatibilityContract,
    reachable: &NamedWires,
) {
    let surfaces = contract
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with("record.named."))
        .collect::<Vec<_>>();
    let declared = surfaces
        .iter()
        .map(|surface| surface.id.as_str())
        .collect::<BTreeSet<_>>();
    let expected = NAMED_SURFACE_IDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        declared, expected,
        "record.named surface inventory must equal the exported named-object closure"
    );
    assert_eq!(
        reachable.keys().copied().collect::<BTreeSet<_>>(),
        expected,
        "typed Op/EventKind traversal must reach every declared named-object type, and no undeclared type"
    );

    for surface in surfaces {
        let direct = match surface.id.as_str() {
            "record.named.image-content" => {
                typed_named_fixture_wires::<ImageContent>(root, surface)
            }
            "record.named.message" => typed_named_fixture_wires::<Message>(root, surface),
            "record.named.provider-state" => {
                typed_named_fixture_wires::<ProviderState>(root, surface)
            }
            "record.named.artifact-ref" => {
                typed_named_fixture_wires::<core_protocol::artifact::ArtifactRef>(root, surface)
            }
            "record.named.provenance" => {
                typed_named_fixture_wires::<core_protocol::artifact::Provenance>(root, surface)
            }
            "record.named.tool-use" => typed_named_fixture_wires::<ToolUse>(root, surface),
            "record.named.tool-result" => typed_named_fixture_wires::<ToolResult>(root, surface),
            "record.named.usage" => typed_named_fixture_wires::<Usage>(root, surface),
            "record.named.durable-environment-context" => {
                typed_named_fixture_wires::<DurableEnvironmentContext>(root, surface)
            }
            "record.named.durable-instruction-context" => {
                typed_named_fixture_wires::<DurableInstructionContext>(root, surface)
            }
            "record.named.workflow-task-evidence" => {
                typed_named_fixture_wires::<WorkflowTaskEvidence>(root, surface)
            }
            "record.named.workflow-metrics" => {
                typed_named_fixture_wires::<WorkflowMetrics>(root, surface)
            }
            "record.named.workflow-cost-evidence" => {
                typed_named_fixture_wires::<WorkflowCostEvidence>(root, surface)
            }
            "record.named.budget" => typed_named_fixture_wires::<Budget>(root, surface),
            "record.named.permission-rules" => {
                typed_named_fixture_wires::<PermissionRules>(root, surface)
            }
            "record.named.pricing-route" => {
                typed_named_fixture_wires::<PricingRoute>(root, surface)
            }
            "record.named.token-rate-card" => {
                typed_named_fixture_wires::<TokenRateCard>(root, surface)
            }
            "record.named.rate-card" => typed_named_fixture_wires::<RateCard>(root, surface),
            "record.named.signed-rate-card" => {
                typed_named_fixture_wires::<SignedRateCard>(root, surface)
            }
            "record.named.cost-projection-identity" => {
                typed_named_fixture_wires::<CostProjectionIdentity>(root, surface)
            }
            "record.named.cost-projection" => {
                typed_named_fixture_wires::<CostProjection>(root, surface)
            }
            unknown => panic!("named surface `{unknown}` lacks a typed dispatch"),
        };
        let reachable = reachable.get(surface.id.as_str()).unwrap_or_else(|| {
            panic!("{} is absent from typed Op/EventKind traversal", surface.id)
        });
        for wire in direct {
            assert!(
                reachable.contains(&wire),
                "direct fixture for {} is not an exact canonical value reachable from typed Op/EventKind: {wire}",
                surface.id
            );
        }
    }
}

fn schema_v3() -> u32 {
    3
}

#[derive(Deserialize, Serialize)]
struct ChainedCurrentShape {
    #[serde(default = "schema_v3", skip_deserializing)]
    version: u32,
    #[serde(rename = "final", alias = "old", alias = "middle")]
    final_value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    added: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct AdditiveCurrentShape {
    #[serde(default = "schema_v3", skip_deserializing)]
    version: u32,
    stable: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    added: Option<String>,
}

#[test]
fn d13_14_runtime_oracle_composes_renames_and_allows_later_additive_defaults() {
    let fields = || {
        vec![
            CompatibilityField {
                name: "version".into(),
            },
            CompatibilityField {
                name: "final".into(),
            },
            CompatibilityField {
                name: "added".into(),
            },
        ]
    };
    let v1 = CompatibilityFixture {
        path: "v1.json".into(),
        format: FixtureFormat::Json,
        schema_version: 1,
    };
    let chained = CompatibilitySurface {
        id: "test.chained".into(),
        current_version: 3,
        version_field: Some("version".into()),
        selector: None,
        fixtures: vec![],
        fields: fields(),
        compatibility_shims: vec![
            CompatibilityShim {
                old_field: "middle".into(),
                replacement: Some("final".into()),
                target_version: 3,
                fixtures: vec!["v2.json".into()],
            },
            CompatibilityShim {
                old_field: "old".into(),
                replacement: Some("middle".into()),
                target_version: 2,
                fixtures: vec![v1.path.clone()],
            },
        ],
    };
    let (_, encoded) = typed_stable::<ChainedCurrentShape>(
        &serde_json::json!({"version": 1, "old": "preserved"}),
        &chained,
        &v1,
        "chained v1 fixture",
    );
    assert_eq!(
        encoded,
        serde_json::json!({"version": 3, "final": "preserved"})
    );
    assert!(
        std::panic::catch_unwind(|| {
            canonical_current_projection(
                &serde_json::json!({
                    "version": 1,
                    "old": "must-not-win",
                    "middle": "must-not-be-overwritten"
                }),
                &chained,
                &v1,
                "replacement collision",
            )
        })
        .is_err(),
        "the runtime oracle must reject a rename collision"
    );

    let v2 = CompatibilityFixture {
        path: "v2.json".into(),
        format: FixtureFormat::Json,
        schema_version: 2,
    };
    let additive = CompatibilitySurface {
        id: "test.additive".into(),
        current_version: 3,
        version_field: Some("version".into()),
        selector: None,
        fixtures: vec![],
        fields: vec![
            CompatibilityField {
                name: "version".into(),
            },
            CompatibilityField {
                name: "stable".into(),
            },
            CompatibilityField {
                name: "added".into(),
            },
        ],
        compatibility_shims: vec![],
    };
    let (_, encoded) = typed_stable::<AdditiveCurrentShape>(
        &serde_json::json!({"version": 2, "stable": "preserved"}),
        &additive,
        &v2,
        "unshimmed additive v2 fixture",
    );
    assert_eq!(
        encoded,
        serde_json::json!({"version": 3, "stable": "preserved"})
    );
}

#[test]
fn d13_14_physical_payload_projection_is_recursively_lossless() {
    let physical = serde_json::json!({
        "kind": {
            "kind": "sample",
            "items": [{"stable": "preserved"}],
        },
    });
    let additive_projection = serde_json::json!({
        "seq": 1,
        "kind": {
            "kind": "sample",
            "items": [{"stable": "preserved", "new_default": false}],
            "new_default": null,
        },
    });
    assert_recursive_projection_preserves(
        &physical,
        &additive_projection,
        "synthetic physical payload",
        "payload",
    );

    for lossy_projection in [
        serde_json::json!({"kind": {"kind": "sample", "items": [{}]}}),
        serde_json::json!({"kind": {"kind": "sample", "items": []}}),
        serde_json::json!({"kind": {"kind": "changed", "items": [{"stable": "preserved"}]}}),
    ] {
        assert!(
            std::panic::catch_unwind(|| {
                assert_recursive_projection_preserves(
                    &physical,
                    &lossy_projection,
                    "synthetic physical payload",
                    "payload",
                )
            })
            .is_err(),
            "a dropped, resized, or changed physical value must fail closed"
        );
    }
}

fn event_kind_tag(kind: &EventKind) -> Option<&'static str> {
    Some(match kind {
        EventKind::Phase { phase: _ } => "phase",
        EventKind::TurnStart => "turn_start",
        EventKind::Message { message: _ } => "message",
        EventKind::Compaction { messages: _ } => "compaction",
        EventKind::Text { delta: _ } => "text",
        EventKind::Thinking { delta: _ } => "thinking",
        EventKind::ToolReady {
            tool: _,
            purity_pure: _,
        } => "tool_ready",
        EventKind::ToolDone {
            result: _,
            effect_id: _,
        } => "tool_done",
        EventKind::EffectIntent {
            id: _,
            tool_use_id: _,
            tool: _,
            capability: _,
            arguments: _,
            workspace: _,
        } => "effect_intent",
        EventKind::EffectUnknown {
            id: _,
            tool: _,
            reason: _,
        } => "effect_unknown",
        EventKind::EffectDone { id: _, tool: _, .. } => "effect_done",
        EventKind::ArtifactProduced { artifact: _ } => "artifact_produced",
        EventKind::EffectFailed {
            id: _,
            tool: _,
            reason: _,
            ..
        } => "effect_failed",
        EventKind::TurnEnd { usage: _, .. } => "turn_end",
        EventKind::Notice { text: _ } => "notice",
        EventKind::SubmissionRejected { reason: _ } => "submission_rejected",
        EventKind::Approval {
            id: _,
            tool_use_id: _,
            tool: _,
            capability: _,
            arguments: _,
            workspace: _,
            verdict: _,
        } => "approval",
        EventKind::RunStart {
            cwd: _,
            model: _,
            effort: _,
            created_at: _,
            environment: _,
            parent_run: _,
            forked_at: _,
            parent_hash_at_seq: _,
            config_digest: _,
            agent_definition_tag: _,
            max_usd: _,
        } => "run_start",
        EventKind::ModelSelected {
            provider_id: _,
            model_id: _,
            catalog_digest: _,
            capability_digest: _,
        } => "model_selected",
        EventKind::RateCardBound { rate_card: _ } => "rate_card_bound",
        EventKind::CostProjected { projection: _ } => "cost_projected",
        EventKind::UsdCeilingChanged {
            version: _,
            source: _,
            max_microusd: _,
        } => "usd_ceiling_changed",
        EventKind::EffortChanged {
            version: _,
            source: _,
            effort: _,
        } => "effort_changed",
        EventKind::PolicyChanged {
            version: _,
            source: _,
            mode: _,
            rules: _,
        } => "policy_changed",
        EventKind::ContextInjection {
            text: _,
            trust: _,
            instructions: _,
        } => "context_injection",
        EventKind::Checkpoint { at: _, tree_ref: _ } => "checkpoint",
        EventKind::SubagentSpawned {
            sub_run: _,
            agent: _,
        } => "subagent_spawned",
        EventKind::SubagentFinished {
            sub_run: _,
            outcome: _,
            metrics: _,
            error_code: _,
            error_detail: _,
            summary_digest: _,
            evidence_bytes: _,
        } => "subagent_finished",
        EventKind::SubagentFinishedV2 {
            version: _,
            sub_run: _,
            outcome: _,
            metrics: _,
            error_code: _,
            error_detail: _,
            summary_digest: _,
            evidence_bytes: _,
        } => "subagent_finished_v2",
        EventKind::Workflow {
            version: _,
            workflow_id: _,
            event: _,
        } => "workflow",
        EventKind::WorkflowV2 {
            version: _,
            workflow_id: _,
            event: _,
        } => "workflow_v2",
        EventKind::Done { outcome: _ } => "done",
        EventKind::Unknown => return None,
    })
}

fn record_blocks(
    message: &Message,
    seen: &mut BTreeSet<&'static str>,
    wires: &mut BTreeSet<String>,
    named: &mut NamedWires,
) {
    record_named(named, "record.named.message", message);
    for block in &message.content {
        wires.insert(canonical_wire(block));
        let tag = match block {
            Block::Text { text: _ } => "text",
            Block::Thinking { thinking: _ } => "thinking",
            Block::ProviderState(state) => {
                record_named(named, "record.named.provider-state", state);
                "provider_state"
            }
            Block::ToolUse(tool) => {
                record_named(named, "record.named.tool-use", tool);
                "tool_use"
            }
            Block::ToolResult(result) => {
                record_named(named, "record.named.tool-result", result);
                "tool_result"
            }
        };
        seen.insert(tag);
    }
}

fn record_op_named_values(op: &Op, named: &mut NamedWires) {
    match op {
        Op::UserInputV2 { segments } => {
            for image in segments.images() {
                record_named(named, "record.named.image-content", image);
            }
        }
        Op::UserInput { text: _ }
        | Op::ApprovalResponse {
            id: _,
            approved: _,
            remember: _,
        }
        | Op::Steer { text: _ }
        | Op::Interrupt
        | Op::Drain
        | Op::Unknown => {}
    }
}

fn workflow_event_tag(event: &WorkflowEvent) -> &'static str {
    match event {
        WorkflowEvent::Started { name: _, class: _ } => "started",
        WorkflowEvent::Planned {
            mode: _,
            tasks: _,
            dropped: _,
            duplicates_removed: _,
            invalid_removed: _,
            fan_turn_budget: _,
            writer_turn_reserve: _,
            fan_wall_secs: _,
            writer_wall_reserve_secs: _,
        } => "planned",
        WorkflowEvent::PhaseChanged { phase: _ } => "phase_changed",
        WorkflowEvent::ChildStarted {
            task_id: _,
            sub_run: _,
            spawn_seq: _,
            budget: _,
        } => "child_started",
        WorkflowEvent::ChildFinished {
            task_id: _,
            sub_run: _,
            outcome: _,
            metrics: _,
            error_code: _,
            error_detail: _,
            summary_digest: _,
            evidence_bytes: _,
        } => "child_finished",
        WorkflowEvent::Reduced {
            evidence_message_seq: _,
            done: _,
            failed: _,
            skipped: _,
            elapsed_ms: _,
        } => "reduced",
        WorkflowEvent::Finished {
            outcome: _,
            metrics: _,
            elapsed_ms: _,
            error_code: _,
            error_detail: _,
        } => "finished",
    }
}

fn record_projection_attribution(
    projection: &CostProjection,
    seen: &mut BTreeSet<&'static str>,
    wires: &mut BTreeSet<String>,
    named: &mut NamedWires,
) {
    record_named(named, "record.named.cost-projection", projection);
    record_named(named, "record.named.pricing-route", &projection.route);
    record_named(named, "record.named.usage", &projection.usage);
    let identity = projection
        .identity
        .as_ref()
        .expect("compatibility projection carries authenticated rollout identity");
    record_named(named, "record.named.cost-projection-identity", identity);
    let attribution = identity
        .attribution
        .as_ref()
        .expect("compatibility projection carries authenticated child attribution");
    wires.insert(canonical_wire(attribution));
    seen.insert(match attribution {
        CostAttribution::DirectSubagent {
            parent_run_id: _,
            sub_run: _,
        } => "direct_subagent",
        CostAttribution::WorkflowChild {
            parent_run_id: _,
            workflow_id: _,
            task_id: _,
            sub_run: _,
        } => "workflow_child",
    });
}

fn record_workflow_metrics(
    metrics: &WorkflowMetrics,
    seen_cost: &mut bool,
    attributions: &mut BTreeSet<&'static str>,
    attribution_wires: &mut BTreeSet<String>,
    named: &mut NamedWires,
) {
    record_named(named, "record.named.workflow-metrics", metrics);
    record_named(named, "record.named.usage", &metrics.usage);
    let Some(cost) = &metrics.cost else {
        return;
    };
    record_named(named, "record.named.workflow-cost-evidence", cost);
    *seen_cost = true;
    assert!(cost.amount_microusd > 0);
    assert!(!cost.rate_card_digest.is_empty());
    assert!(!cost.projections.is_empty());
    for projection in &cost.projections {
        record_projection_attribution(projection, attributions, attribution_wires, named);
    }
}

fn record_signed_rate_card(rate_card: &SignedRateCard, named: &mut NamedWires) {
    record_named(named, "record.named.signed-rate-card", rate_card);
    record_named(named, "record.named.rate-card", &rate_card.rate_card);
    record_named(
        named,
        "record.named.pricing-route",
        &rate_card.rate_card.route,
    );
    record_named(
        named,
        "record.named.token-rate-card",
        &rate_card.rate_card.rates,
    );
}

fn record_workflow_named_values(
    event: &WorkflowEvent,
    seen_cost: &mut bool,
    attributions: &mut BTreeSet<&'static str>,
    attribution_wires: &mut BTreeSet<String>,
    named: &mut NamedWires,
) {
    match event {
        WorkflowEvent::Planned { tasks, .. } => {
            for task in tasks {
                record_named(named, "record.named.workflow-task-evidence", task);
            }
        }
        WorkflowEvent::ChildStarted { budget, .. } => {
            record_named(named, "record.named.budget", budget);
        }
        WorkflowEvent::ChildFinished { metrics, .. } | WorkflowEvent::Finished { metrics, .. } => {
            record_workflow_metrics(metrics, seen_cost, attributions, attribution_wires, named)
        }
        WorkflowEvent::Started { .. }
        | WorkflowEvent::PhaseChanged { .. }
        | WorkflowEvent::Reduced { .. } => {}
    }
}

fn expected(values: &[&'static str]) -> BTreeSet<&'static str> {
    values.iter().copied().collect()
}

#[test]
fn d13_14_event_schema_corpora_are_exact_exhaustive_and_replayable() {
    let root = repository_root();
    let contract = compatibility_contract(&root);
    let envelope_surface = contract
        .surfaces
        .iter()
        .find(|surface| surface.id == "record.event-envelope")
        .expect("record.event-envelope surface is declared");
    let rollout_surface = contract
        .surfaces
        .iter()
        .find(|surface| surface.id == "record.rollout")
        .expect("record.rollout surface is declared");
    let kind_surfaces = contract
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with("record.event-kind."))
        .collect::<Vec<_>>();
    assert!(
        !kind_surfaces.is_empty(),
        "event-kind surfaces are declared"
    );

    let mut kind_wires = BTreeSet::new();
    let mut envelope_kind_wires = BTreeSet::new();
    let mut envelope_wires = BTreeSet::new();
    let mut replayed_wires = BTreeSet::new();
    let mut writable_tags = BTreeSet::new();
    let mut block_tags = BTreeSet::new();
    let mut workflow_tags = BTreeSet::new();
    let mut cost_attribution_tags = BTreeSet::new();
    let mut workflow_cost_seen = false;
    let mut nested_block_wires = BTreeSet::new();
    let mut nested_workflow_wires = BTreeSet::new();
    let mut nested_attribution_wires = BTreeSet::new();
    let mut named_wires = NamedWires::new();

    for surface in contract
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with("protocol.op."))
    {
        let selector = surface
            .selector
            .as_ref()
            .expect("every protocol.op surface has a selector");
        assert_eq!(selector.field, "op", "{} selector field", surface.id);
        for fixture in &surface.fixtures {
            for (index, raw) in selected_fixture_values(&root, surface, fixture)
                .into_iter()
                .enumerate()
            {
                let label = format!(
                    "{} fixture {} schema {} object {}",
                    surface.id,
                    fixture.path,
                    fixture.schema_version,
                    index + 1
                );
                let (op, _) = typed_stable::<Op>(&raw, surface, fixture, &label);
                record_op_named_values(&op, &mut named_wires);
            }
        }
    }

    for surface in kind_surfaces {
        let selector = surface
            .selector
            .as_ref()
            .expect("every record.event-kind surface has a selector");
        assert_eq!(selector.field, "kind", "{} selector field", surface.id);
        for fixture in &surface.fixtures {
            for (index, raw) in selected_fixture_values(&root, surface, fixture)
                .into_iter()
                .enumerate()
            {
                let label = format!(
                    "{} fixture {} schema {} object {}",
                    surface.id,
                    fixture.path,
                    fixture.schema_version,
                    index + 1
                );
                let (kind, encoded) = typed_stable::<EventKind>(&raw, surface, fixture, &label);
                kind.validate_compatibility_tag()
                    .unwrap_or_else(|error| panic!("{label} is not writable: {error}"));
                let tag = event_kind_tag(&kind)
                    .unwrap_or_else(|| panic!("{label} decoded as the Unknown sentinel"));
                assert_eq!(tag, selector.value, "{label} selected the wrong typed tag");
                writable_tags.insert(tag);
                kind_wires.insert(serde_json::to_string(&encoded).unwrap());
                match &kind {
                    EventKind::Message { message } => {
                        record_blocks(
                            message,
                            &mut block_tags,
                            &mut nested_block_wires,
                            &mut named_wires,
                        );
                    }
                    EventKind::Compaction { messages } => {
                        for message in messages {
                            record_blocks(
                                message,
                                &mut block_tags,
                                &mut nested_block_wires,
                                &mut named_wires,
                            );
                        }
                    }
                    EventKind::ArtifactProduced { artifact } => {
                        record_named(&mut named_wires, "record.named.artifact-ref", artifact);
                        record_named(
                            &mut named_wires,
                            "record.named.provenance",
                            &artifact.provenance,
                        );
                    }
                    EventKind::ToolReady { tool, .. } => {
                        record_named(&mut named_wires, "record.named.tool-use", tool);
                    }
                    EventKind::ToolDone { result, .. } => {
                        record_named(&mut named_wires, "record.named.tool-result", result);
                    }
                    EventKind::TurnEnd { usage, .. } => {
                        record_named(&mut named_wires, "record.named.usage", usage);
                    }
                    EventKind::RunStart {
                        environment: Some(environment),
                        ..
                    } => record_named(
                        &mut named_wires,
                        "record.named.durable-environment-context",
                        environment,
                    ),
                    EventKind::RateCardBound { rate_card } => {
                        record_signed_rate_card(rate_card, &mut named_wires);
                    }
                    EventKind::CostProjected { projection } => {
                        record_projection_attribution(
                            projection,
                            &mut cost_attribution_tags,
                            &mut nested_attribution_wires,
                            &mut named_wires,
                        );
                    }
                    EventKind::PolicyChanged { rules, .. } => {
                        record_named(&mut named_wires, "record.named.permission-rules", rules);
                    }
                    EventKind::ContextInjection {
                        instructions: Some(instructions),
                        ..
                    } => {
                        record_named(
                            &mut named_wires,
                            "record.named.durable-instruction-context",
                            instructions,
                        );
                        if let Some(environment) = &instructions.environment {
                            record_named(
                                &mut named_wires,
                                "record.named.durable-environment-context",
                                environment,
                            );
                        }
                    }
                    EventKind::SubagentFinished { metrics, .. }
                    | EventKind::SubagentFinishedV2 { metrics, .. } => record_workflow_metrics(
                        metrics,
                        &mut workflow_cost_seen,
                        &mut cost_attribution_tags,
                        &mut nested_attribution_wires,
                        &mut named_wires,
                    ),
                    EventKind::Workflow { event, .. } | EventKind::WorkflowV2 { event, .. } => {
                        workflow_tags.insert(workflow_event_tag(event));
                        nested_workflow_wires.insert(canonical_wire(event));
                        record_workflow_named_values(
                            event,
                            &mut workflow_cost_seen,
                            &mut cost_attribution_tags,
                            &mut nested_attribution_wires,
                            &mut named_wires,
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    for fixture in &envelope_surface.fixtures {
        for (index, raw) in selected_fixture_values(&root, envelope_surface, fixture)
            .into_iter()
            .enumerate()
        {
            let label = format!(
                "{} fixture {} schema {} object {}",
                envelope_surface.id,
                fixture.path,
                fixture.schema_version,
                index + 1
            );
            let (event, encoded) = typed_stable::<Event>(&raw, envelope_surface, fixture, &label);
            event
                .kind
                .validate_compatibility_tag()
                .unwrap_or_else(|error| panic!("{label} contains an unwritable kind: {error}"));
            envelope_kind_wires
                .insert(serde_json::to_string(encoded.get("kind").unwrap()).unwrap());
            envelope_wires.insert(serde_json::to_string(&encoded).unwrap());
        }
    }

    for fixture in &rollout_surface.fixtures {
        assert!(
            matches!(fixture.format, FixtureFormat::Jsonl),
            "record rollout fixture {} must be JSONL",
            fixture.path
        );
        let path = root.join(&fixture.path);
        let physical = fixture_values(&root, fixture);
        let replayed = replay(&path).unwrap_or_else(|error| {
            panic!("rollout fixture {} failed replay: {error}", path.display())
        });
        assert_eq!(
            replayed.len(),
            physical.len(),
            "rollout fixture {} lost records",
            fixture.path
        );
        assert!(
            !replayed.is_empty(),
            "rollout fixture {} is empty",
            fixture.path
        );
        for (index, (physical_record, event)) in physical.iter().zip(replayed).enumerate() {
            let encoded = serde_json::to_value(&event).unwrap();
            let label = format!(
                "record.rollout fixture {} schema {} event {}",
                fixture.path,
                fixture.schema_version,
                index + 1
            );
            let (_, stable) = typed_roundtrip::<Event>(&encoded, &label);
            let physical_payload = physical_record
                .get("payload")
                .unwrap_or_else(|| panic!("{label} physical record lacks `payload`"));
            assert_recursive_projection_preserves(physical_payload, &stable, &label, "payload");
            replayed_wires.insert(serde_json::to_string(&stable).unwrap());
        }
    }

    assert_eq!(writable_tags, expected(&WRITABLE_EVENT_TAGS));
    assert_eq!(
        kind_wires, envelope_kind_wires,
        "every typed event-kind fixture must occur in the typed envelope corpus, and vice versa"
    );
    for envelope in envelope_wires {
        assert!(
            replayed_wires.contains(&envelope),
            "typed event-envelope fixture is absent from every replayed rollout: {envelope}"
        );
    }
    assert_eq!(block_tags, expected(&BLOCK_TAGS));
    assert_eq!(workflow_tags, expected(&WORKFLOW_EVENT_TAGS));
    assert!(
        workflow_cost_seen,
        "WorkflowCostEvidence must be non-null in the corpus"
    );
    assert_eq!(
        cost_attribution_tags,
        expected(&COST_ATTRIBUTION_TAGS),
        "every tagged CostAttribution variant must occur in the corpus"
    );
    assert_eq!(
        typed_surface_wires::<Block>(&root, &contract, "record.block.", "type"),
        nested_block_wires,
        "Block fixture projections must equal the exact values nested in EventKind"
    );
    assert_eq!(
        typed_surface_wires::<WorkflowEvent>(&root, &contract, "record.workflow-event.", "event",),
        nested_workflow_wires,
        "WorkflowEvent fixture projections must equal the exact values nested in EventKind"
    );
    assert_eq!(
        typed_surface_wires::<CostAttribution>(
            &root,
            &contract,
            "record.cost-attribution.",
            "kind",
        ),
        nested_attribution_wires,
        "CostAttribution fixture projections must equal the exact values nested in EventKind"
    );
    assert_named_surface_corpus(&root, &contract, &named_wires);
}

fn hash_line(prev: &str, seq: u64, payload: &Value) -> String {
    let mut hash = Sha256::new();
    hash.update(prev.as_bytes());
    hash.update(seq.to_le_bytes());
    hash.update(payload.to_string().as_bytes());
    hex::encode(hash.finalize())
}

#[test]
fn d13_14_future_event_tag_is_a_content_free_replay_sentinel() {
    let marker = "future-payload-must-not-survive-decoding";
    let payload = serde_json::json!({
        "seq": 0,
        "turn": 0,
        "kind": {
            "kind": "future_event_v999",
            "opaque": marker,
            "nested": {"credential": marker}
        }
    });
    let line = serde_json::json!({
        "seq": 0,
        "tenant": "default",
        "prev": ZERO_HASH,
        "hash": hash_line(ZERO_HASH, 0, &payload),
        "payload": payload
    });
    let path = std::env::temp_dir().join(format!(
        "core-d13-14-future-event-{}-{}.jsonl",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("{line}\n")).expect("future-event rollout fixture writes");
    let replayed = replay(&path).expect("a future top-level event tag must not fail replay");
    std::fs::remove_file(&path).ok();

    assert_eq!(replayed.len(), 1);
    assert!(matches!(replayed[0].kind, EventKind::Unknown));
    let encoded = serde_json::to_value(&replayed[0]).unwrap();
    assert_eq!(encoded["kind"], serde_json::json!({"kind": "unknown"}));
    assert!(!encoded.to_string().contains(marker));
}
