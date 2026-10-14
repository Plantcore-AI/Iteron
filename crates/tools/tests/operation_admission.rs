use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::intent::ToolIntent;
use iteron_protocol::slot::SlotId;
use iteron_protocol::{Capability, Purity, ToolResult, ToolSpec, ToolUse, Trust};
use iteron_tools::{Registry, ToolPolicy, boxfut};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn all() -> CapabilitySet {
    CapabilitySet::from_iter_capabilities([
        Capability::ReadOnly,
        Capability::ReversibleLocal,
        Capability::CodeExecuting,
        Capability::TrustMutating,
        Capability::IrreversibleExternal,
    ])
}

fn admitted(call: ToolUse, capabilities: CapabilitySet) -> ToolIntent {
    let mut intent = ToolIntent::denied(
        SlotId("core/tool_policy".into()),
        call,
        Purity::Effecting,
        Trust::Trusted,
    );
    intent.admitted = capabilities;
    intent
}

#[tokio::test]
async fn every_dispatch_path_refuses_a_shell_grant_that_omits_actual_effects() {
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let executed = Arc::new(AtomicUsize::new(0));
    let seen = executed.clone();
    registry
        .register_external(
            ToolSpec {
                name: "bash".into(),
                description: "test executor; never starts a process".into(),
                input_schema: json!({"type":"object"}),
                purity: Purity::Effecting,
                capability: Capability::CodeExecuting,
            },
            move |call, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                boxfut::box_it(async move {
                    ToolResult {
                        tool_use_id: call.id,
                        content: "executed".into(),
                        is_error: false,
                        trust: Trust::Workspace,
                        latency_ms: 0,
                    }
                })
            },
        )
        .unwrap();
    let call = ToolUse {
        id: "opaque-shell".into(),
        name: "bash".into(),
        input: json!({"command":"python untrusted.py", "writes":[]}),
    };
    let code_only = CapabilitySet::only(Capability::CodeExecuting);
    assert!(
        registry
            .propose_intent(
                &ToolPolicy::default(),
                call.clone(),
                Trust::Trusted,
                code_only
            )
            .is_err()
    );
    assert!(
        registry
            .dispatch_intent(admitted(call.clone(), code_only))
            .await
            .is_error
    );
    assert!(
        registry
            .run_admitted_intent(admitted(call.clone(), code_only))
            .await
            .into_result()
            .is_error
    );
    assert!(
        registry
            .dispatch_stream_intent(admitted(call.clone(), code_only))
            .await
            .into_result()
            .is_error
    );
    assert_eq!(executed.load(Ordering::SeqCst), 0);

    let proposal = registry
        .propose_intent(&ToolPolicy::default(), call, Trust::Trusted, all())
        .unwrap();
    assert!(proposal.eligible.contains(Capability::IrreversibleExternal));
    assert!(
        !registry
            .run_admitted_intent(proposal.admit(all()))
            .await
            .into_result()
            .is_error
    );
    assert_eq!(executed.load(Ordering::SeqCst), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn a_path_retargeted_to_trust_data_is_rechecked_before_executor_construction() {
    use std::os::unix::fs::symlink;
    let root =
        std::env::temp_dir().join(format!("iteron-operation-retarget-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("AGENTS.md"), "operator-owned instructions").unwrap();
    std::fs::write(root.join("notes.txt"), "ordinary data").unwrap();
    let registry = Registry::coding_agent(&root).unwrap();
    let call = ToolUse {
        id: "write".into(),
        name: "write_file".into(),
        input: json!({"path":"notes.txt", "content":"replacement"}),
    };
    let local = CapabilitySet::only(Capability::ReversibleLocal);
    let proposal = registry
        .propose_intent(&ToolPolicy::default(), call, Trust::Trusted, local)
        .unwrap();
    std::fs::remove_file(root.join("notes.txt")).unwrap();
    symlink("AGENTS.md", root.join("notes.txt")).unwrap();
    let result = registry
        .run_admitted_intent(proposal.admit(local))
        .await
        .into_result();
    assert!(result.is_error);
    assert!(result.content.contains("operation capability admission"));
    assert_eq!(
        std::fs::read_to_string(root.join("AGENTS.md")).unwrap(),
        "operator-owned instructions"
    );
    std::fs::remove_dir_all(root).unwrap();
}
