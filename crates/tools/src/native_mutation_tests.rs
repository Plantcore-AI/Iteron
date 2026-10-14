use super::NativeReceiptWire;
use crate::{CapturedToolExecution, McpEffectAttribution, Registry, ToolExecution, capturedfut};
use iteron_protocol::{Capability, Purity, ToolSpec, ToolUse};
use serde_json::json;
use sha2::{Digest as _, Sha256};
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
        let mut input = json!({"path":path,"content":text});
        if let Some(before) = expected_before {
            input["expected_sha256"] = json!(format!("{:x}", Sha256::digest(before)));
        }
        let captured = registry
            .run_effect_captured(call(id, "write_file", input))
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
async fn actual_existing_dirty_file_requires_a_preimage_and_preserves_all_bytes() {
    let root = TestRoot::new();
    let original = b"user header\nuser dirty body\nuser footer\n";
    std::fs::write(root.0.join("dirty.txt"), original).unwrap();
    let registry = registry(&root, false);
    for (id, extra, expected_kind) in [
        ("no-preimage", json!({}), "preimage_required"),
        (
            "old-preimage",
            json!({"expected_sha256":format!("{:x}",Sha256::digest(b"old clean body\n"))}),
            "preimage_changed",
        ),
    ] {
        let mut input = json!({"path":"dirty.txt","content":"blind whole replacement\n"});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let result = registry
            .run_effect_captured(call(id, "write_file", input))
            .await;
        let ToolExecution::Definite(ref failed) = result.execution else {
            panic!("{result:?}")
        };
        assert!(failed.is_error);
        assert_eq!(failed.tool_use_id, id);
        let refusal: serde_json::Value = serde_json::from_str(&failed.content).unwrap();
        assert_eq!(refusal["kind"], expected_kind);
        assert!(result.native_mutation.is_none());
        assert_eq!(std::fs::read(root.0.join("dirty.txt")).unwrap(), original);
        assert_eq!(
            std::fs::read_dir(&root.0).unwrap().count(),
            1,
            "no staged replacement remains"
        );
    }
}

#[tokio::test]
async fn actual_read_witness_binds_raw_bom_crlf_bytes_and_explicit_replacement() {
    let root = TestRoot::new();
    let original = b"\xef\xbb\xbfuser header\r\nuser dirty body\r\nuser footer";
    std::fs::write(root.0.join("dirty.txt"), original).unwrap();
    let registry = registry(&root, false);
    let mut policy = crate::ObservationToolPolicy::default();
    policy.read_file.output_max_bytes = 512;
    registry.install_observation_tool_policy(policy).unwrap();
    let default = registry
        .run(call("plain-read", "read_file", json!({"path":"dirty.txt"})))
        .await;
    assert!(!default.is_error, "{}", default.content);
    assert!(!default.content.contains("raw_sha256="));
    let read = registry
        .run(call(
            "witness",
            "read_file",
            json!({"path":"dirty.txt","include_sha256":true,"limit":1}),
        ))
        .await;
    assert!(!read.is_error, "{}", read.content);
    let digest = format!("{:x}", Sha256::digest(original));
    assert!(
        read.content
            .starts_with(&format!("raw_sha256=sha256-{digest}\n     1\tuser header"))
    );
    assert!(read.content.contains("truncated before line 2"));
    assert!(read.content.len() <= 512);
    // Caller explicitly supplies the full plain UTF-8 replacement; the hash still binds the original BOM bytes.
    let replacement = "user header\r\nuser dirty body preserved and updated\r\nuser footer";
    let result = registry
        .run_effect_captured(call(
            "deliberate",
            "write_file",
            json!({"path":"dirty.txt","content":replacement,"expected_sha256":digest}),
        ))
        .await;
    definite_success(&result);
    let receipt = result.native_mutation.unwrap();
    assert_eq!(receipt.files()[0].before(), Some(original.as_slice()));
    assert_eq!(receipt.files()[0].after(), replacement.as_bytes());
    assert_eq!(
        std::fs::read(root.0.join("dirty.txt")).unwrap(),
        replacement.as_bytes()
    );
}

#[tokio::test]
async fn actual_read_witness_does_not_relax_argument_or_preimage_validation() {
    let root = TestRoot::new();
    let original = b"42\n";
    std::fs::write(root.0.join("strict.txt"), original).unwrap();
    let registry = registry(&root, false);
    let read = registry
        .run(call(
            "invalid-boolean",
            "read_file",
            json!({"path":"strict.txt","include_sha256":"True"}),
        ))
        .await;
    assert!(read.is_error);
    assert!(!read.content.contains("raw_sha256="));
    let digest = format!("{:x}", Sha256::digest(original));
    for (id, expected_sha256) in [
        ("prefixed-token", format!("sha256-{digest}")),
        ("entire-header", format!("raw_sha256=sha256-{digest}")),
    ] {
        let captured = registry
            .run_effect_captured(call(
                id,
                "write_file",
                json!({"path":"strict.txt","content":"replacement","expected_sha256":expected_sha256}),
            ))
            .await;
        assert!(matches!(&captured.execution, ToolExecution::Definite(result) if result.is_error));
        assert!(captured.native_mutation.is_none());
        assert_eq!(std::fs::read(root.0.join("strict.txt")).unwrap(), original);
    }
}

#[tokio::test]
async fn actual_human_edit_after_read_refuses_stale_whole_replacement() {
    let root = TestRoot::new();
    std::fs::write(root.0.join("race.txt"), b"before\n").unwrap();
    let registry = registry(&root, false);
    registry
        .install_observation_tool_policy(crate::ObservationToolPolicy::default())
        .unwrap();
    let read = registry
        .run(call(
            "before-read",
            "read_file",
            json!({"path":"race.txt","include_sha256":true}),
        ))
        .await;
    assert!(!read.is_error, "{}", read.content);
    let digest = read
        .content
        .lines()
        .next()
        .unwrap()
        .strip_prefix("raw_sha256=sha256-")
        .unwrap();
    std::fs::write(root.0.join("race.txt"), b"human!\n").unwrap();
    let result = registry
        .run_effect_captured(call(
            "stale-write",
            "write_file",
            json!({"path":"race.txt","content":"agent replacement\n","expected_sha256":digest}),
        ))
        .await;
    assert!(
        matches!(&result.execution,ToolExecution::Definite(result)if result.is_error&&result.content.contains("preimage_changed"))
    );
    assert!(result.native_mutation.is_none());
    assert_eq!(std::fs::read(root.0.join("race.txt")).unwrap(), b"human!\n");
}

#[tokio::test]
async fn actual_existing_preimage_cannot_authorize_a_missing_file() {
    let root = TestRoot::new();
    let registry = registry(&root, false);
    let result=registry.run_effect_captured(call("expected-existing","write_file",json!({"path":"absent.txt","content":"replacement","expected_sha256":format!("{:x}",Sha256::digest(b"before"))}))).await;
    assert!(
        matches!(&result.execution,ToolExecution::Definite(result)if result.is_error&&result.content.contains("preimage_changed"))
    );
    assert!(result.native_mutation.is_none());
    assert!(!root.0.join("absent.txt").exists());
    let created = registry
        .run_effect_captured(call(
            "create-only",
            "write_file",
            json!({"path":"absent.txt","content":"new"}),
        ))
        .await;
    definite_success(&created);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn actual_confined_helper_enforces_the_same_caller_preimage() {
    let root = TestRoot::new();
    let original = b"user dirty\n";
    std::fs::write(root.0.join("dirty.txt"), original).unwrap();
    let registry = registry(&root, true);
    let refused = registry
        .run_effect_captured(call(
            "confined-blind",
            "write_file",
            json!({"path":"dirty.txt","content":"overwrite\n"}),
        ))
        .await;
    assert!(
        matches!(&refused.execution,ToolExecution::Definite(result)if result.is_error&&result.content.contains("preimage_required")),
        "{refused:?}"
    );
    assert!(refused.native_mutation.is_none());
    assert_eq!(std::fs::read(root.0.join("dirty.txt")).unwrap(), original);
    let accepted=registry.run_effect_captured(call("confined-bound","write_file",json!({"path":"dirty.txt","content":"user dirty preserved\n","expected_sha256":format!("{:x}",Sha256::digest(original))}))).await;
    definite_success(&accepted);
    assert_eq!(
        accepted.native_mutation.unwrap().files()[0].before(),
        Some(original.as_slice())
    );
    assert_eq!(
        std::fs::read(root.0.join("dirty.txt")).unwrap(),
        b"user dirty preserved\n"
    );
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
        crate::write_file::WritePreimage::CurrentSnapshot,
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
