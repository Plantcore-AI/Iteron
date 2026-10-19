//! Real journal/ledger tests for the intercepted-call lifetime; no fake terminal is injected.
use crate::runtime::context_runtime::ContextBudgetInspection;
use crate::runtime::{Agent, DurableAppendFault, KernelError, gate_integration_tests};
use iteron_protocol::{
    Budget, Capability, EventKind, RunId, TenantId, ToolResult, ToolUse, Trust, TurnId,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
use std::sync::Arc;
struct NoTransport;
#[async_trait::async_trait]
impl Provider for NoTransport {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("intercepted tool call must not spend provider IO")
    }
}
fn agent(label: &str) -> Agent {
    let workspace = gate_integration_tests::temp_ws(label);
    let rollout = iteron_record::Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId(label.into()),
        TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        Arc::new(NoTransport),
        iteron_tools::Registry::coding_agent_for_tests(&workspace).unwrap(),
        rollout,
        "fixture".into(),
        "fixture".into(),
        Budget::default(),
    );
    agent.workspace = workspace;
    gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent.guard_unresolved_effects().unwrap();
    agent
}
fn call() -> ToolUse {
    ToolUse {
        id: "plan-inspection".into(),
        name: iteron_tools::UPDATE_PLAN.into(),
        input: serde_json::json!({"operation":"inspect"}),
    }
}
#[test]
fn real_plan_call_is_journaled_and_counted_once_with_zero_serial_overlap() {
    let mut agent = agent("kernel-plan-once");
    let call = call();
    let projection = agent.turn_result_projection_budget(
        ContextBudgetInspection::from_policy(Default::default(), Default::default()),
        std::slice::from_ref(&call),
    );
    let admitted = agent
        .kernel_tool_call(TurnId(1), 0, &call, Capability::ReversibleLocal, projection)
        .unwrap();
    let mut result = agent.execute_task_plan(TurnId(1), &call).unwrap();
    result.latency_ms = 7;
    let result = agent.complete_kernel_tool_call(admitted, result).unwrap();
    assert!(!result.is_error);
    assert_eq!(agent.ledger.tool_calls, 1);
    let timings = agent.ledger.timings().complete().unwrap();
    assert_eq!(timings.tool_wall_ms, 7);
    assert_eq!(timings.tool_overlapped_ms, 0);
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert_eq!(events.iter().filter(|event|matches!(&event.kind,EventKind::EffectIntent {tool,..} if tool==iteron_tools::UPDATE_PLAN)).count(),1);
    assert_eq!(events.iter().filter(|event|matches!(&event.kind,EventKind::ToolDone {tool:Some(tool),..} if tool==iteron_tools::UPDATE_PLAN)).count(),1);
}
#[test]
fn real_terminal_refusal_cannot_increment_the_live_tool_ledger() {
    let mut agent = agent("kernel-plan-terminal-refused");
    let call = call();
    let projection = agent.turn_result_projection_budget(
        ContextBudgetInspection::from_policy(Default::default(), Default::default()),
        std::slice::from_ref(&call),
    );
    let admitted = agent
        .kernel_tool_call(TurnId(1), 0, &call, Capability::ReversibleLocal, projection)
        .unwrap();
    agent.fail_next_durable_append = Some(DurableAppendFault::ToolDone);
    assert!(matches!(
        agent.complete_kernel_tool_call(
            admitted,
            ToolResult {
                tool_use_id: "substituted".into(),
                content: "observed fixture".into(),
                is_error: false,
                trust: Trust::Untrusted,
                latency_ms: 7,
            }
        ),
        Err(KernelError::Record(_))
    ));
    assert_eq!(agent.ledger.tool_calls, 0);
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert!(!events.iter().any(|event|matches!(&event.kind,EventKind::ToolDone {tool:Some(tool),..} if tool==iteron_tools::UPDATE_PLAN)));
}
