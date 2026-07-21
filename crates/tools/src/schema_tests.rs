use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

static NEXT_TEMP_ROOT: AtomicUsize = AtomicUsize::new(0);

fn temp_root(label: &str) -> PathBuf {
    let sequence = NEXT_TEMP_ROOT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "core-schema-{label}-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn object_with_string_path(name: &str, purity: Purity, capability: Capability) -> ToolSpec {
    ToolSpec {
        name: name.into(),
        description: "schema-validation probe".into(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]
        }),
        purity,
        capability,
    }
}

#[tokio::test]
async fn d3_13_g1_missing_edit_field_is_structured_before_executor() {
    let root = temp_root("missing-edit-field");
    let path = root.join("note.txt");
    std::fs::write(&path, "before\n").unwrap();
    let registry = Registry::coding_agent(&root).unwrap();

    let result = registry
        .run(ToolUse {
            id: "missing-old".into(),
            name: "edit".into(),
            input: serde_json::json!({"path": "note.txt", "new": "after\n"}),
        })
        .await;

    assert!(result.is_error);
    assert_eq!(result.tool_use_id, "missing-old");
    let error: serde_json::Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(error["error"], "invalid_tool_arguments");
    assert_eq!(error["kind"], "missing_required_field");
    assert_eq!(error["field"], "old");
    assert!(error["message"].as_str().unwrap().contains("required"));
    assert!(!result.content.contains("anchor an edit on nothing"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "before\n");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn d3_13_g2_and_g4_external_wrong_type_never_reaches_dispatch() {
    let root = temp_root("external-wrong-type");
    let mut registry = Registry::read_only(&root).unwrap();
    let executions = Arc::new(AtomicUsize::new(0));
    let executor_count = executions.clone();
    registry
        .register_external(
            object_with_string_path("external_probe", Purity::Pure, Capability::ReadOnly),
            move |call, _root| {
                let executor_count = executor_count.clone();
                boxfut::box_it(async move {
                    executor_count.fetch_add(1, Ordering::SeqCst);
                    ok_result(call.id, "executor ran".into())
                })
            },
        )
        .unwrap();

    let result = registry
        .dispatch(ToolUse {
            id: "wrong-type".into(),
            name: "external_probe".into(),
            input: serde_json::json!({"path": 17}),
        })
        .await;

    assert!(result.is_error);
    let error: serde_json::Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(error["kind"], "type_mismatch");
    assert_eq!(error["field"], "path");
    assert_eq!(error["expected"], "string");
    assert_eq!(error["actual"], "integer");
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    assert_eq!(
        registry.memo_stats(),
        (0, 0),
        "pre-dispatch rejection must not count as a memoized read attempt"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn d3_13_g3_well_formed_call_reaches_executor_unchanged() {
    let root = temp_root("happy-path");
    let mut registry = Registry::read_only(&root).unwrap();
    let observed = Arc::new(Mutex::new(None));
    let executor_observed = observed.clone();
    registry
        .register_external(
            object_with_string_path("external_happy", Purity::Pure, Capability::ReadOnly),
            move |call, _root| {
                *executor_observed.lock().unwrap() = Some(call.clone());
                boxfut::box_it(async move { ok_result(call.id, "unchanged result".into()) })
            },
        )
        .unwrap();
    let call = ToolUse {
        id: "happy".into(),
        name: "external_happy".into(),
        input: serde_json::json!({"path": "src/lib.rs", "extra": true}),
    };

    let result = registry.dispatch(call.clone()).await;

    assert!(!result.is_error);
    assert_eq!(result.content, "unchanged result");
    assert_eq!(observed.lock().unwrap().as_ref(), Some(&call));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn unsupported_external_schema_fails_closed_at_registration() {
    let root = temp_root("unsupported-schema");
    let mut registry = Registry::read_only(&root).unwrap();
    let spec = ToolSpec {
        name: "unsupported_external".into(),
        description: "must not register".into(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "pattern": "^src/"}
            }
        }),
        purity: Purity::Pure,
        capability: Capability::ReadOnly,
    };

    let error = registry
        .register_external(spec, |call, _root| {
            boxfut::box_it(async move { ok_result(call.id, "must not run".into()) })
        })
        .unwrap_err();

    let message = error.to_string();
    assert!(message.contains("unsupported schema keyword `pattern`"));
    assert!(message.contains("$.properties.path.pattern"));
    assert!(registry.purity_of("unsupported_external").is_none());
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn supported_minimum_is_enforced_before_builtin_read() {
    let root = temp_root("minimum");
    std::fs::write(root.join("note.txt"), "line\n").unwrap();
    let registry = Registry::read_only(&root).unwrap();

    let result = registry
        .dispatch(ToolUse {
            id: "zero-offset".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path": "note.txt", "offset": 0}),
        })
        .await;

    assert!(result.is_error);
    let error: serde_json::Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(error["kind"], "below_minimum");
    assert_eq!(error["field"], "offset");
    assert_eq!(error["minimum"], 1);
    assert_eq!(registry.memo_stats(), (0, 0));
    let _ = std::fs::remove_dir_all(root);
}
