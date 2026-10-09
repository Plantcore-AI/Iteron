use super::*;
use iteron_protocol::{Purity, Trust};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU64};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn workspace() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "iteron-sdk-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn coding(root: &std::path::Path) -> Registry {
    let registry = Registry::coding_agent(root).unwrap();
    registry.test_helper_thread.store(true, Ordering::Release);
    registry
}
fn recipe(name: &str, primitive: &str, fixed: Value, scope: Vec<String>) -> ToolRecipeV1 {
    ToolRecipeV1 {
        version: 1,
        name: name.into(),
        description: "ordinary native projection".into(),
        primitive: primitive.into(),
        fixed_arguments: fixed.as_object().unwrap().clone(),
        write_paths: scope,
    }
}
fn call(name: &str, input: Value) -> ToolUse {
    ToolUse {
        id: "sdk-physical-call".into(),
        name: name.into(),
        input,
    }
}
#[tokio::test]
async fn native_read_projection_cannot_override_immutable_arguments_or_claim_purity() {
    let root = workspace();
    std::fs::write(root.join("f"), "read-anchor").unwrap();
    let mut registry = Registry::read_only(&root).unwrap();
    let native = registry
        .specs()
        .into_iter()
        .find(|spec| spec.name == "read_file")
        .unwrap();
    let spec = registry
        .register_ordinary_recipe(
            recipe("sample__read", "read_file", json!({"path":"f"}), vec![]),
            CapabilitySet::only(Capability::ReadOnly),
            None,
        )
        .unwrap();
    assert_eq!(spec.purity, native.purity);
    assert_eq!(spec.purity, Purity::Pure);
    assert_eq!(spec.capability, native.capability);
    let unconfigured = registry.dispatch(call("sample__read", json!({}))).await;
    assert!(unconfigured.is_error);
    assert!(
        unconfigured
            .content
            .contains("runtime policy was not installed")
    );
    registry
        .install_observation_tool_policy(crate::ObservationToolPolicy::default())
        .unwrap();
    let result = registry.dispatch(call("sample__read", json!({}))).await;
    assert!(!result.is_error);
    assert!(result.content.contains("read-anchor"));
    assert_eq!(result.trust, Trust::Workspace);
    assert!(
        registry
            .dispatch(call("sample__read", json!({"path":"other"})))
            .await
            .is_error
    );
    assert!(
        registry
            .register_ordinary_recipe(
                recipe("sample__fake", "sample__read", json!({}), vec![]),
                CapabilitySet::only(Capability::ReadOnly),
                None
            )
            .is_err()
    );
    assert!(
        registry
            .register_ordinary_recipe(
                recipe("sample__write", "write_file", json!({}), vec!["f".into()]),
                CapabilitySet::only(Capability::ReadOnly),
                None
            )
            .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_native_writer_intersects_scope_and_receipt_keeps_physical_identity() {
    let root = workspace();
    std::fs::create_dir(root.join("src")).unwrap();
    std::fs::create_dir(root.join("other")).unwrap();
    let mut registry = coding(&root);
    registry
        .set_inherited_write_scope(vec!["src".into()])
        .unwrap();
    registry
        .register_ordinary_recipe(
            recipe(
                "sample__write",
                "write_file",
                json!({}),
                vec!["src/f".into(), "other".into()],
            ),
            CapabilitySet::only(Capability::ReversibleLocal),
            None,
        )
        .unwrap();
    let result = registry
        .run_effect_captured(call(
            "sample__write",
            json!({"path":"src/f","content":"actual-native-write"}),
        ))
        .await;
    assert!(!result.execution.into_result().is_error);
    assert_eq!(
        std::fs::read_to_string(root.join("src/f")).unwrap(),
        "actual-native-write"
    );
    let receipt = result.native_mutation.unwrap();
    assert_eq!(receipt.tool_name(), "write_file");
    assert_eq!(receipt.logical_tool_name(), "sample__write");
    assert_eq!(receipt.tool_use_id(), "sdk-physical-call");
    let refused = registry
        .run_effect_captured(call(
            "sample__write",
            json!({"path":"other/f","content":"refused"}),
        ))
        .await;
    assert!(refused.execution.into_result().is_error);
    assert!(!root.join("other/f").exists());
    let scope = registry
        .run_effect_captured(call(
            "sample__write",
            json!({"path":"src/else","content":"refused"}),
        ))
        .await;
    assert!(scope.execution.into_result().is_error);
    assert!(!root.join("src/else").exists());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn fixed_trust_and_opaque_shell_effects_are_classified_from_the_primitive() {
    let root = workspace();
    let mut registry = coding(&root);
    let all = CapabilitySet::from_iter_capabilities([
        Capability::ReadOnly,
        Capability::ReversibleLocal,
        Capability::CodeExecuting,
        Capability::TrustMutating,
        Capability::IrreversibleExternal,
    ]);
    registry
        .register_ordinary_recipe(
            recipe(
                "sample__shell",
                "bash",
                json!({"command":"$(unknown-program)"}),
                vec![],
            ),
            all,
            None,
        )
        .unwrap();
    let effects = registry
        .operation_effects(&call("sample__shell", json!({})))
        .unwrap();
    assert!(effects.required.contains(Capability::TrustMutating));
    assert!(effects.required.contains(Capability::IrreversibleExternal));
    assert_eq!(effects.canonical_tool.as_deref(), Some("bash"));
    registry
        .register_ordinary_recipe(
            recipe(
                "sample__trust",
                "write_file",
                json!({"path":"AGENTS.md"}),
                vec!["src".into()],
            ),
            all,
            None,
        )
        .unwrap();
    let effects = registry
        .operation_effects(&call("sample__trust", json!({"content":"no"})))
        .unwrap();
    assert!(effects.required.contains(Capability::TrustMutating));
    std::fs::remove_dir_all(root).unwrap();
}
#[derive(Debug)]
struct Revoke(AtomicBool);
impl iteron_protocol::extension_dispatch::ExtensionDispatchPolicy for Revoke {
    fn admits(&self, _: iteron_protocol::extension_dispatch::ExtensionSurfaceV1, _: &str) -> bool {
        !self.0.load(Ordering::Acquire)
    }
}
#[tokio::test]
async fn cached_native_read_still_obeys_exact_revocation() {
    let root = workspace();
    std::fs::write(root.join("f"), "old").unwrap();
    let mut registry = Registry::read_only(&root).unwrap();
    registry
        .install_observation_tool_policy(crate::ObservationToolPolicy::default())
        .unwrap();
    let policy = Arc::new(Revoke(AtomicBool::new(false)));
    registry
        .register_ordinary_recipe(
            recipe("sample__read", "read_file", json!({"path":"f"}), vec![]),
            CapabilitySet::only(Capability::ReadOnly),
            Some(policy.clone()),
        )
        .unwrap();
    assert!(
        !registry
            .dispatch(call("sample__read", json!({})))
            .await
            .is_error
    );
    policy.0.store(true, Ordering::Release);
    assert!(
        registry
            .dispatch(call("sample__read", json!({})))
            .await
            .is_error
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn installing_inherited_scope_later_mints_the_current_scope_at_real_dispatch() {
    let root = workspace();
    let mut registry = coding(&root);
    registry
        .register_ordinary_recipe(
            recipe("sample__write", "write_file", json!({}), vec!["f".into()]),
            CapabilitySet::only(Capability::ReversibleLocal),
            None,
        )
        .unwrap();
    registry
        .set_inherited_write_scope(vec!["f".into()])
        .unwrap();
    let result = registry
        .dispatch(call(
            "sample__write",
            json!({"path":"f","content":"scoped"}),
        ))
        .await;
    assert!(!result.is_error);
    assert_eq!(std::fs::read_to_string(root.join("f")).unwrap(), "scoped");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_strategy_evidence_uses_actual_fixed_recipe_arguments() {
    let root = workspace();
    let mut registry = coding(&root);
    registry
        .register_ordinary_recipe(
            recipe(
                "sample__write",
                "write_file",
                json!({"path":"f"}),
                vec!["f".into()],
            ),
            CapabilitySet::only(Capability::ReversibleLocal),
            None,
        )
        .unwrap();
    let write = call("sample__write", json!({"content":"next"}));
    assert!(registry.is_candidate_change_tool(&write.name));
    assert_eq!(
        registry.workspace_candidate_paths(&write, &root).unwrap(),
        vec![root.canonicalize().unwrap().join("f")]
    );
    assert!(
        registry
            .workspace_candidate_paths(
                &call("sample__write", json!({"path":"outside","content":"next"})),
                &root
            )
            .is_none()
    );
    registry
        .register_ordinary_recipe(
            recipe("sample__read", "read_file", json!({"path":"f"}), Vec::new()),
            CapabilitySet::only(Capability::ReadOnly),
            None,
        )
        .unwrap();
    let read = call("sample__read", json!({}));
    assert!(registry.is_candidate_review_tool(&read.name));
    assert!(registry.is_workspace_localization_observation(&read, &root));
    assert!(registry.is_workspace_targeted_observation(&read, &root));
    std::fs::remove_dir_all(root).unwrap();
}
