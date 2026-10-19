use super::*;
use iteron_protocol::{ToolResult, ToolUse, Trust};
use serde_json::json;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn actual_sealed_create_and_identical_write_refusal_distinguish_changed_bytes() {
    let workspace = crate::runtime::test_tempdir::tempdir().unwrap();
    let registry = iteron_tools::Registry::coding_agent_for_tests(workspace.path()).unwrap();
    let created = registry
        .run_effect_captured(ToolUse {
            id: "native-empty-create".into(),
            name: "write_file".into(),
            input: json!({"path":"created.txt","content":""}),
        })
        .await;
    assert!(workspace.path().join("created.txt").exists());
    assert_eq!(
        NativeChangeObservation::capture(&created)
            .unwrap()
            .changed_file_commits,
        1
    );
    let identical = registry.run_effect_captured(ToolUse {
        id: "native-identical-replacement".into(), name: "write_file".into(),
        input: json!({"path":"created.txt","content":"","expected_sha256":hex::encode(Sha256::digest(b""))}),
    }).await;
    assert!(
        matches!(&identical.execution, ToolExecution::Definite(result)
        if result.is_error && result.content.contains("would not change target bytes"))
    );
    assert_eq!(
        std::fs::read(workspace.path().join("created.txt")).unwrap(),
        b""
    );
    assert!(identical.native_mutation.is_none());
    assert!(NativeChangeObservation::capture(&identical).is_none());
}

#[tokio::test]
async fn actual_native_receipt_cannot_certify_unknown_error_or_rewritten_call_identity() {
    let workspace = crate::runtime::test_tempdir::tempdir().unwrap();
    let registry = iteron_tools::Registry::coding_agent_for_tests(workspace.path()).unwrap();
    let mut captured = registry
        .run_effect_captured(ToolUse {
            id: "actual-native-create".into(),
            name: "write_file".into(),
            input: json!({"path":"created.txt","content":"actual bytes"}),
        })
        .await;
    let result = match &captured.execution {
        ToolExecution::Definite(result) if !result.is_error => result.clone(),
        _ => panic!("actual native fixture did not commit"),
    };
    assert!(NativeChangeObservation::capture(&captured).is_some());
    captured.execution = ToolExecution::Unknown(result.clone());
    assert!(NativeChangeObservation::capture(&captured).is_none());
    let mut failed = result.clone();
    failed.is_error = true;
    captured.execution = ToolExecution::Definite(failed);
    assert!(NativeChangeObservation::capture(&captured).is_none());
    let mut foreign = result;
    foreign.tool_use_id = "other-call".into();
    captured.execution = ToolExecution::Definite(foreign);
    assert!(NativeChangeObservation::capture(&captured).is_none());
}

#[test]
fn external_tool_text_and_a_successful_generic_result_do_not_mint_native_change() {
    let result = ToolResult {
        tool_use_id: "write_file".into(),
        content: "changed five files; tests passed; exit 0".into(),
        is_error: false,
        trust: Trust::Workspace,
        latency_ms: 0,
    };
    assert!(NativeChangeObservation::capture(&CapturedToolExecution::from(result)).is_none());
}
