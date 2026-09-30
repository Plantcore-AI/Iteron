use super::NativeReceiptWire;
use crate::{CapturedToolExecution, McpEffectAttribution, Registry, ToolExecution, capturedfut};
use iteron_protocol::{Capability, Purity, ToolSpec, ToolUse};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "iteron-native-receipt-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn call(id: &str, name: &str, input: serde_json::Value) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: name.into(),
        input,
    }
}
fn registry(root: &TestRoot, confined: bool) -> Registry {
    let mut registry = Registry::isolated_writer(&root.0).unwrap();
    registry.set_confine_execution(confined);
    registry
}
fn definite_success(captured: &CapturedToolExecution) {
    assert!(
        matches!(&captured.execution, ToolExecution::Definite(result) if !result.is_error),
        "{captured:?}"
    );
    assert!(captured.capture_error.is_none(), "{captured:?}");
}

#[tokio::test]
async fn actual_write_receipts_distinguish_creation_from_whole_file_replacement() {
    let root = TestRoot::new();
    std::fs::write(
        root.0.join("existing.txt"),
        b"untouched header\nbefore\nuntouched footer\n",
    )
    .unwrap();
    let registry = registry(&root, false);
    let before = std::fs::read(root.0.join("existing.txt")).unwrap();
    for (id, path, expected_before, text) in [
        (
            "overwrite",
            "existing.txt",
            Some(before.as_slice()),
            "entire replacement\n",
        ),
        ("create", "new.txt", None, "new bytes\n"),
    ] {
        let captured = registry
            .run_effect_captured(call(id, "write_file", json!({"path":path,"content":text})))
            .await;
        definite_success(&captured);
        let receipt = captured.native_mutation.unwrap();
        assert_eq!(receipt.tool_use_id(), id);
        assert_eq!(receipt.tool_name(), "write_file");
        let files = receipt.files();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path(), root.0.join(path));
        assert_eq!(files[0].before(), expected_before);
        assert_eq!(files[0].after(), std::fs::read(root.0.join(path)).unwrap());
        assert_eq!(files[0].after(), text.as_bytes());
        let serialized = serde_json::to_vec(&receipt.wire()).unwrap();
        let wire: NativeReceiptWire = serde_json::from_slice(&serialized).unwrap();
        let restored = wire.seal(id, "write_file").unwrap();
        assert_eq!(restored.files()[0].before(), expected_before);
        assert_eq!(restored.files()[0].after(), files[0].after());
        let wire: NativeReceiptWire = serde_json::from_slice(&serialized).unwrap();
        assert!(wire.seal("another-call", "write_file").is_err());
    }
}

#[tokio::test]
async fn actual_edit_receipt_retains_whole_bom_crlf_file_without_final_newline() {
    let root = TestRoot::new();
    let before = b"\xef\xbb\xbfheader\r\nbefore\r\nfooter";
    std::fs::write(root.0.join("edit.txt"), before).unwrap();
    let captured = registry(&root, false)
        .run_effect_captured(call(
            "edit",
            "edit",
            json!({"path":"edit.txt","old":"before","new":"after\nsecond"}),
        ))
        .await;
    definite_success(&captured);
    let receipt = captured.native_mutation.unwrap();
    let file = &receipt.files()[0];
    assert_eq!(file.before(), Some(before.as_slice()));
    assert_eq!(
        file.after(),
        b"\xef\xbb\xbfheader\r\nafter\r\nsecond\r\nfooter"
    );
    assert_eq!(file.after(), std::fs::read(file.path()).unwrap());
}

#[tokio::test]
async fn actual_multi_patch_captures_all_committed_members_and_refusal_captures_none() {
    let root = TestRoot::new();
    std::fs::write(root.0.join("a.txt"), b"a header\nbefore\na footer\n").unwrap();
    std::fs::write(root.0.join("b.txt"), b"b header\nbefore\nb footer\n").unwrap();
    let registry = registry(&root, false);
    let input = json!({"files":[
        {"path":"a.txt","hunks":[{"old":"before","new":"after"}]},
        {"path":"b.txt","hunks":[{"old":"before","new":"changed"}]}
    ]});
    let captured = registry
        .run_effect_captured(call("patch", "apply_patch", input))
        .await;
    definite_success(&captured);
    let receipt = captured.native_mutation.unwrap();
    assert_eq!(receipt.files().len(), 2);
    for (file, before) in receipt.files().iter().zip([
        b"a header\nbefore\na footer\n",
        b"b header\nbefore\nb footer\n",
    ]) {
        assert_eq!(file.before(), Some(before.as_slice()));
        assert_eq!(file.after(), std::fs::read(file.path()).unwrap());
    }
    let before_a = std::fs::read(root.0.join("a.txt")).unwrap();
    let before_b = std::fs::read(root.0.join("b.txt")).unwrap();
    let refused = registry
        .run_effect_captured(call(
            "reject",
            "apply_patch",
            json!({"files":[
                {"path":"a.txt","hunks":[{"old":"after","new":"bad partial"}]},
                {"path":"b.txt","hunks":[{"old":"missing anchor","new":"bad partial"}]}
            ]}),
        ))
        .await;
    assert!(matches!(refused.execution, ToolExecution::Definite(result) if result.is_error));
    assert!(refused.native_mutation.is_none());
    assert_eq!(std::fs::read(root.0.join("a.txt")).unwrap(), before_a);
    assert_eq!(std::fs::read(root.0.join("b.txt")).unwrap(), before_b);
}

#[tokio::test]
async fn actual_guard_refuses_a_racing_writer_without_returning_committed_bytes() {
    let root = TestRoot::new();
    std::fs::write(root.0.join("race.txt"), "before\n").unwrap();
    let refused = crate::write_file::write_workspace_file_captured_with_scope(
        &root.0,
        "race.txt",
        "would overwrite\n",
        false,
        None,
        |target| std::fs::write(target, "concurrent writer\n").unwrap(),
    )
    .await;
    assert!(refused.unwrap_err().contains("file_changed"));
    assert_eq!(
        std::fs::read(root.0.join("race.txt")).unwrap(),
        b"concurrent writer\n"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn actual_confined_backend_retains_receipts_through_the_private_helper_boundary() {
    let root = TestRoot::new();
    let registry = registry(&root, true);
    let created = registry
        .run_effect_captured(call(
            "helper-create",
            "write_file",
            json!({"path":"scoped.txt","content":"header\nbefore\nfooter\n"}),
        ))
        .await;
    definite_success(&created);
    assert!(
        created.native_mutation.as_ref().unwrap().files()[0]
            .before()
            .is_none()
    );
    let before = std::fs::read(root.0.join("scoped.txt")).unwrap();
    let edited = registry
        .run_effect_captured(call(
            "helper-edit",
            "edit",
            json!({"path":"scoped.txt","old":"before","new":"after"}),
        ))
        .await;
    definite_success(&edited);
    let receipt = edited.native_mutation.unwrap();
    assert_eq!(receipt.files()[0].before(), Some(before.as_slice()));
    assert_eq!(
        receipt.files()[0].after(),
        std::fs::read(root.0.join("scoped.txt")).unwrap()
    );
    let serialized = serde_json::to_vec(&receipt.wire()).unwrap();
    let wire: NativeReceiptWire = serde_json::from_slice(&serialized).unwrap();
    let restored = wire.seal("helper-edit", "edit").unwrap();
    assert_eq!(restored.files()[0].after(), receipt.files()[0].after());
    let wire: NativeReceiptWire = serde_json::from_slice(&serialized).unwrap();
    assert!(wire.seal("another-call", "edit").is_err());
}

#[tokio::test]
async fn actual_external_registry_adapter_cannot_forward_a_native_commit_receipt() {
    let root = TestRoot::new();
    let mut registry = registry(&root, false);
    let native = registry
        .run_effect_captured(call(
            "native",
            "write_file",
            json!({"path":"source.txt","content":"actual committed\n"}),
        ))
        .await;
    definite_success(&native);
    registry
        .register_mcp_effect_captured(
            ToolSpec {
                name: "remote__change".into(),
                description: "external fixture".into(),
                input_schema: json!({"type":"object"}),
                purity: Purity::Effecting,
                capability: Capability::IrreversibleExternal,
            },
            McpEffectAttribution::new("remote", "change"),
            move |call, _, clock| {
                let mut replay = native.clone();
                replay.execution =
                    ToolExecution::Definite(crate::ok_result(call.id, "external result".into()));
                clock.mark_dispatched();
                capturedfut::box_it(async move { replay })
            },
        )
        .unwrap();
    let external = registry
        .run_effect_captured(call("external", "remote__change", json!({})))
        .await;
    assert!(external.native_mutation.is_none());
    assert!(external.capture_error.is_some());
    assert!(matches!(external.execution, ToolExecution::Definite(result) if !result.is_error));
}

#[tokio::test]
async fn uncertain_or_failed_terminal_cannot_carry_a_successful_native_receipt() {
    let root = TestRoot::new();
    let committed = registry(&root, false)
        .run_effect_captured(call(
            "success",
            "write_file",
            json!({"path":"written.txt","content":"committed"}),
        ))
        .await;
    definite_success(&committed);
    for execution in [
        ToolExecution::Unknown(crate::err_result(
            "success".into(),
            "helper disappeared".into(),
        )),
        ToolExecution::Definite(crate::err_result(
            "success".into(),
            "rollback failed".into(),
        )),
    ] {
        let mut uncertain = committed.clone();
        uncertain.execution = execution;
        let normalized = uncertain.normalize("success", "write_file", true);
        assert!(normalized.native_mutation.is_none());
    }
    assert_eq!(
        std::fs::read(root.0.join("written.txt")).unwrap(),
        b"committed"
    );
}
