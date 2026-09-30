use super::ToolAdmissionDecision;
use crate::runtime::inbound_control::TurnSubmission;
use crate::runtime::ordered_tool_call::OrderedCallAdmission;
use crate::runtime::{Agent, Budget, KernelError, UiEvent};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{
    Capability, EventKind, Op, PermissionMode, RunId, SubmissionId, TenantId, ToolUse, Trust,
    TurnId,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
use iteron_record::Rollout;
use std::{path::PathBuf, sync::Arc, time::Duration};

struct NoProviderIo;
#[async_trait::async_trait]
impl Provider for NoProviderIo {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("tool admission has no provider dispatch authority");
    }
}
fn fixture() -> (PathBuf, Agent, ToolUse) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "iteron-tool-admission-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    let rollout = Rollout::open(
        &root.join(".iteron/runs"),
        &RunId("admission".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        Arc::new(NoProviderIo),
        iteron_tools::Registry::coding_agent_for_tests(&root).unwrap(),
        rollout,
        "fixture".into(),
        "system".into(),
        Budget {
            max_turns: 5,
            max_usd: None,
            max_tokens: None,
            max_wall_secs: 30,
            max_consecutive_tool_errors: 5,
        },
    );
    agent.workspace = root.clone();
    let call = ToolUse {
        id: "real-local-write".into(),
        name: "write_file".into(),
        input: serde_json::json!({"path":"result.txt","content":"exact admitted native mutation"}),
    };
    (root, agent, call)
}
fn proposal(
    agent: &Agent,
    call: &ToolUse,
) -> Result<iteron_tools::ToolPolicyProposal, iteron_tools::ToolPolicyError> {
    crate::runtime::strategy_runtime::propose_tool(
        &agent.registry,
        agent.tool_policy.as_ref(),
        call.clone(),
        Trust::Workspace,
    )
}

#[tokio::test]
async fn actual_plan_gate_and_noninteractive_ask_publish_only_refused_tool_done() {
    for mode in [PermissionMode::Plan, PermissionMode::Default] {
        let (root, mut agent, call) = fixture();
        agent.permission_mode = mode;
        agent.interactive_approvals = false;
        let draft = proposal(&agent, &call);
        let decision = agent
            .tool_declaration_admission(TurnId(0), Trust::Workspace)
            .run(&call, draft)
            .await
            .unwrap();
        assert!(matches!(decision, ToolAdmissionDecision::Refused(_)));
        assert!(!root.join("result.txt").exists());
        let events = iteron_record::replay(agent.rollout.path()).unwrap();
        assert!(events.iter().any(|event| matches!(&event.kind, EventKind::ToolDone { result, effect_id:None, .. } if result.tool_use_id == call.id && result.is_error)));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.kind, EventKind::EffectIntent { .. }))
        );
        drop(agent);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn real_operator_remember_barrier_precedes_the_actual_native_executor() {
    let (root, mut agent, call) = fixture();
    agent.permission_mode = PermissionMode::Default;
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    agent.set_approvals(rx);
    let (ui, mut reader) = tokio::sync::mpsc::channel(16);
    agent.set_ui(ui);
    let draft = proposal(&agent, &call);
    let (decision, _) = tokio::join!(
        async {
            agent
                .tool_declaration_admission(TurnId(0), Trust::Workspace)
                .run(&call, draft)
                .await
        },
        async {
            loop {
                let event = tokio::time::timeout(Duration::from_secs(2), reader.recv())
                    .await
                    .unwrap()
                    .unwrap();
                if let UiEvent::ApprovalRequest { id, .. } = event {
                    tx.send(TurnSubmission::identified(
                        SubmissionId(11),
                        Op::ApprovalResponse {
                            id,
                            approved: true,
                            remember: true,
                        },
                    ))
                    .await
                    .unwrap();
                    break;
                }
            }
        }
    );
    let ToolAdmissionDecision::Permitted {
        proposal,
        capability,
        action_signature,
    } = decision.unwrap()
    else {
        panic!("durably approved local operation must return its permit");
    };
    assert!(
        !root.join("result.txt").exists(),
        "a permission barrier itself executes no tool"
    );
    let admitted = iteron_record::replay(agent.rollout.path()).unwrap();
    let approval = admitted
        .iter()
        .find(|event| {
            matches!(
                event.kind,
                EventKind::Approval {
                    verdict: iteron_protocol::Verdict::Auto,
                    ..
                }
            )
        })
        .unwrap()
        .seq;
    let remembered = admitted
        .iter()
        .find(|event| {
            matches!(
                event.kind,
                EventKind::PolicyChanged {
                    source: iteron_protocol::RuntimePolicySource::ApprovalRemember,
                    ..
                }
            )
        })
        .unwrap()
        .seq;
    assert!(remembered.0 > approval.0);
    let estimate = agent
        .context_estimator
        .estimate_uncached("system", &[], &[]);
    let inspection = agent.inspect_context_budget(&[], &estimate);
    let projection = agent.turn_result_projection_budget(inspection, std::slice::from_ref(&call));
    let result = agent
        .ordered_tool_call(TurnId(0), &call.name, false, projection)
        .execute(OrderedCallAdmission {
            index: 0,
            capability,
            action_signature,
            intent: proposal.admit(CapabilitySet::only(capability)),
        })
        .await
        .unwrap();
    assert!(!result.result.is_error, "{}", result.result.content);
    assert_eq!(
        std::fs::read_to_string(root.join("result.txt")).unwrap(),
        "exact admitted native mutation"
    );
    let intent = iteron_record::replay(agent.rollout.path())
        .unwrap()
        .into_iter()
        .find(|event| matches!(event.kind, EventKind::EffectIntent { .. }))
        .unwrap()
        .seq;
    assert!(intent.0 > remembered.0);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn a_proposal_for_different_arguments_cannot_cross_the_owner_boundary() {
    let (root, mut agent, call) = fixture();
    agent.permission_mode = PermissionMode::AcceptEdits;
    let mut different = call.clone();
    different.input["path"] = serde_json::json!("other.txt");
    let draft = proposal(&agent, &different);
    let result = agent
        .tool_declaration_admission(TurnId(0), Trust::Workspace)
        .run(&call, draft)
        .await;
    assert!(matches!(result, Err(KernelError::EffectBoundary(_))));
    assert!(!root.join("result.txt").exists() && !root.join("other.txt").exists());
    assert!(
        !iteron_record::replay(agent.rollout.path())
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, EventKind::EffectIntent { .. }))
    );
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
