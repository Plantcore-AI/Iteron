use core_protocol::{EqEnvelope, Op, SqEnvelope};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

struct Fixture {
    path: PathBuf,
    relative: String,
    schema_version: u64,
    current_version: u64,
    version_field: Option<String>,
    active_fields: BTreeSet<String>,
    shims: Vec<Value>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root exists")
}

fn fixture_contract(root: &Path, surface: &Value, fixture: &Value) -> Fixture {
    let relative = fixture["path"].as_str().expect("fixture path is a string");
    Fixture {
        path: root.join(relative),
        relative: relative.to_owned(),
        schema_version: fixture["schema_version"]
            .as_u64()
            .expect("fixture schema version"),
        current_version: surface["current_version"]
            .as_u64()
            .expect("surface current version"),
        version_field: surface["version_field"].as_str().map(str::to_owned),
        active_fields: surface["fields"]
            .as_array()
            .expect("surface fields")
            .iter()
            .map(|field| field["name"].as_str().expect("field name").to_owned())
            .collect(),
        shims: surface["compatibility_shims"]
            .as_array()
            .expect("compatibility shims is an array")
            .clone(),
    }
}

fn fixtures(surface_id: &str) -> Vec<Fixture> {
    let root = root();
    let contract: Value = serde_json::from_slice(
        &std::fs::read(root.join("governance/schema-compatibility.json"))
            .expect("compatibility contract is readable"),
    )
    .expect("compatibility contract is JSON");
    let surface = contract["surfaces"]
        .as_array()
        .expect("surfaces is an array")
        .iter()
        .find(|surface| surface["id"] == surface_id)
        .expect("protocol surface is declared");
    surface["fixtures"]
        .as_array()
        .expect("fixtures is an array")
        .iter()
        .map(|fixture| fixture_contract(&root, surface, fixture))
        .collect()
}

fn assert_typed_matches_current_projection(
    original: &Value,
    canonical: &Value,
    fixture: &Fixture,
    label: &str,
) {
    let raw = original.as_object().expect("fixture object");
    let mut target = raw.clone();
    let mut shims = fixture.shims.iter().collect::<Vec<_>>();
    shims.sort_by(|left, right| {
        (
            left["target_version"]
                .as_u64()
                .expect("shim target version"),
            left["old_field"].as_str().expect("shim old field"),
        )
            .cmp(&(
                right["target_version"]
                    .as_u64()
                    .expect("shim target version"),
                right["old_field"].as_str().expect("shim old field"),
            ))
    });
    for shim in shims {
        let old_field = shim["old_field"].as_str().expect("shim old field");
        let Some(old) = target.remove(old_field) else {
            continue;
        };
        if raw.contains_key(old_field) {
            assert!(
                shim["fixtures"]
                    .as_array()
                    .expect("shim fixtures")
                    .iter()
                    .any(|path| path.as_str() == Some(&fixture.relative)),
                "{label} uses `{old_field}` without declaring the fixture on its shim"
            );
        }
        if let Some(replacement) = shim["replacement"].as_str() {
            assert!(
                !target.contains_key(replacement),
                "{label} migration would overwrite replacement field `{replacement}`"
            );
            target.insert(replacement.to_owned(), old);
        }
        if let Some(version_field) = fixture.version_field.as_deref() {
            target.insert(
                version_field.to_owned(),
                Value::from(
                    shim["target_version"]
                        .as_u64()
                        .expect("shim target version"),
                ),
            );
        }
    }
    if let Some(version_field) = fixture.version_field.as_deref() {
        target.insert(
            version_field.to_owned(),
            Value::from(fixture.current_version),
        );
    }
    let target_fields = target.keys().cloned().collect::<BTreeSet<_>>();
    assert!(
        target_fields.is_subset(&fixture.active_fields),
        "{label} migration retained stale or undeclared fields"
    );
    let encoded = canonical.as_object().expect("typed encoding object");
    let encoded_fields = encoded.keys().cloned().collect::<BTreeSet<_>>();
    assert!(
        encoded_fields.is_subset(&fixture.active_fields),
        "{label} typed encoding emitted undeclared fields"
    );
    for (field, value) in target {
        assert_eq!(
            encoded.get(&field),
            Some(&value),
            "{label} typed current serialization changed traceable field `{field}`"
        );
    }
    if fixture.schema_version == fixture.current_version {
        assert_eq!(
            canonical, original,
            "{label} current-version wire shape changed"
        );
    }
}

#[test]
fn d13_14_sq_envelope_corpus_round_trips() {
    for fixture in fixtures("protocol.sq-envelope") {
        let original: Value =
            serde_json::from_slice(&std::fs::read(&fixture.path).unwrap()).unwrap();
        let first: SqEnvelope = serde_json::from_value(original.clone()).unwrap();
        let canonical = serde_json::to_value(&first).unwrap();
        let second: SqEnvelope = serde_json::from_value(canonical.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(second).unwrap(),
            canonical,
            "{}",
            fixture.path.display()
        );
        assert_typed_matches_current_projection(
            &original,
            &canonical,
            &fixture,
            &fixture.path.display().to_string(),
        );
    }
}

#[test]
fn d13_14_eq_envelope_corpus_round_trips() {
    for fixture in fixtures("protocol.eq-envelope") {
        let original: Value =
            serde_json::from_slice(&std::fs::read(&fixture.path).unwrap()).unwrap();
        let first: EqEnvelope = serde_json::from_value(original.clone()).unwrap();
        let canonical = serde_json::to_value(&first).unwrap();
        let second: EqEnvelope = serde_json::from_value(canonical.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(second).unwrap(),
            canonical,
            "{}",
            fixture.path.display()
        );
        assert_typed_matches_current_projection(
            &original,
            &canonical,
            &fixture,
            &fixture.path.display().to_string(),
        );
    }
}

fn op_tag(op: &Op) -> &'static str {
    match op {
        Op::UserInput { .. } => "user_input",
        Op::UserInputV2 { .. } => "user_input_v2",
        Op::ApprovalResponse { .. } => "approval_response",
        Op::Steer { .. } => "steer",
        Op::Interrupt => "interrupt",
        Op::Drain => "drain",
        Op::Unknown => "unknown",
    }
}

fn fixture_values(path: &Path, format: &str) -> Vec<Value> {
    let bytes = std::fs::read(path).unwrap();
    match format {
        "json" => vec![serde_json::from_slice(&bytes).unwrap()],
        "jsonl" => std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect(),
        other => panic!("unsupported fixture format {other}"),
    }
}

#[test]
fn d13_14_every_manifest_sq_op_fixture_typed_round_trips() {
    let root = root();
    let contract: Value = serde_json::from_slice(
        &std::fs::read(root.join("governance/schema-compatibility.json")).unwrap(),
    )
    .unwrap();
    let mut declared_tags = BTreeSet::new();
    for surface in contract["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|surface| {
            surface["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("protocol.op."))
        })
    {
        let selector = surface["selector"].as_object().unwrap();
        assert_eq!(selector["field"], "op");
        let tag = selector["value"].as_str().unwrap();
        assert!(declared_tags.insert(tag.to_owned()), "duplicate tag {tag}");
        for fixture in surface["fixtures"].as_array().unwrap() {
            let relative = fixture["path"].as_str().unwrap();
            let fixture_contract = fixture_contract(&root, surface, fixture);
            let mut matches = 0usize;
            for original in
                fixture_values(&root.join(relative), fixture["format"].as_str().unwrap())
            {
                if original.get("op").and_then(Value::as_str) != Some(tag) {
                    continue;
                }
                matches += 1;
                let first: Op = serde_json::from_value(original.clone()).unwrap();
                assert_eq!(op_tag(&first), tag);
                let canonical = serde_json::to_value(&first).unwrap();
                let second: Op = serde_json::from_value(canonical.clone()).unwrap();
                assert_eq!(serde_json::to_value(&second).unwrap(), canonical);
                assert!(SqEnvelope::current(second).into_current().is_ok());
                assert_typed_matches_current_projection(
                    &original,
                    &canonical,
                    &fixture_contract,
                    relative,
                );
            }
            assert!(matches > 0, "{relative} has no op={tag} record");
        }
    }
    assert_eq!(
        declared_tags,
        BTreeSet::from([
            "approval_response".to_owned(),
            "drain".to_owned(),
            "interrupt".to_owned(),
            "steer".to_owned(),
            "user_input".to_owned(),
            "user_input_v2".to_owned(),
        ])
    );

    let future: Op = serde_json::from_value(serde_json::json!({
        "op": "future_submission",
        "opaque": "must not survive"
    }))
    .unwrap();
    assert!(matches!(future, Op::Unknown));
    assert!(!serde_json::to_string(&future).unwrap().contains("opaque"));
}

#[test]
fn d13_14_protocol_runtime_oracle_composes_shims_and_rejects_value_loss() {
    let fixture = Fixture {
        path: PathBuf::from("v1.json"),
        relative: "v1.json".into(),
        schema_version: 1,
        current_version: 3,
        version_field: Some("version".into()),
        active_fields: BTreeSet::from(["added".into(), "final".into(), "version".into()]),
        shims: vec![
            serde_json::json!({
                "old_field": "middle",
                "replacement": "final",
                "target_version": 3,
                "fixtures": ["v2.json"]
            }),
            serde_json::json!({
                "old_field": "old",
                "replacement": "middle",
                "target_version": 2,
                "fixtures": ["v1.json"]
            }),
        ],
    };
    assert_typed_matches_current_projection(
        &serde_json::json!({"version": 1, "old": "preserved"}),
        &serde_json::json!({"version": 3, "final": "preserved"}),
        &fixture,
        "chained protocol fixture",
    );

    assert!(
        std::panic::catch_unwind(|| {
            assert_typed_matches_current_projection(
                &serde_json::json!({
                    "version": 1,
                    "old": "must-not-win",
                    "middle": "must-not-be-overwritten"
                }),
                &serde_json::json!({"version": 3, "final": "must-not-win"}),
                &fixture,
                "protocol replacement collision",
            );
        })
        .is_err(),
        "a protocol shim must never overwrite an existing replacement value"
    );
}
