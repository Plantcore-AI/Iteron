//! Actual host special execution journeys; model responses are controlled, journals are native.
use super::{KernelSpecialKind, KernelSpecialResult};
use crate::runtime::context_runtime::ContextBudgetInspection;
use crate::runtime::{Agent, KernelError, gate_integration_tests};
use iteron_protocol::{
    Block, Budget, Capability, EventKind, RunId, StopReason, TenantId, ToolUse, Trust, TurnId,
    Usage,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
struct Answer(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl Provider for Answer {
    fn provider_instance_id(&self) -> Option<&str> {
        Some("fixture-provider")
    }
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(TurnResult {
            blocks: vec![Block::Text {
                text: "actual child report".into(),
            }],
            stop_reason: StopReason::EndTurn,
            usage: UsageReport::complete(Usage {
                input: 1,
                output: 2,
                ..Default::default()
            }),
        })
    }
}
fn host(label: &str) -> (Agent, Arc<AtomicUsize>) {
    let workspace = gate_integration_tests::temp_ws(label);
    let calls = Arc::new(AtomicUsize::new(0));
    let rollout = iteron_record::Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId(label.into()),
        TenantId("kernel-fixture".into()),
    )
    .unwrap();
    let mut host = Agent::new(
        Arc::new(Answer(calls.clone())),
        iteron_tools::Registry::coding_agent_for_tests(&workspace).unwrap(),
        rollout,
        "fixture-model".into(),
        "fixture system".into(),
        Budget::default(),
    );
    host.workspace = workspace;
    host.provider_selection.fixture_selection(
        Some(crate::runtime::provider_selection::SelectedRoute {
            route: iteron_protocol::PricingRoute {
                provider_id: "fixture-provider".into(),
                model_id: "fixture-model".into(),
                catalog_digest: String::new(),
                capability_digest: String::new(),
            },
        }),
        host.provider.clone(),
    );
    let workspace = host.workspace.clone();
    gate_integration_tests::record_test_genesis(&mut host, &workspace);
    host.record_model_selection(
        "fixture-provider".into(),
        "fixture-model".into(),
        String::new(),
        String::new(),
    )
    .unwrap();
    host.guard_unresolved_effects().unwrap();
    (host, calls)
}
async fn execute(
    host: &mut Agent,
    kind: KernelSpecialKind,
    call: &ToolUse,
) -> Result<iteron_protocol::ToolResult, KernelError> {
    let projection = host.turn_result_projection_budget(
        ContextBudgetInspection::from_policy(Default::default(), Default::default()),
        std::slice::from_ref(call),
    );
    let (execution, output) = host.kernel_special_execution(TurnId(1), 0, kind, projection);
    Ok(
        match execution
            .run(
                TurnId(1),
                0,
                call,
                match kind {
                    KernelSpecialKind::Plan => Capability::ReversibleLocal,
                    _ => Capability::CodeExecuting,
                },
                output,
            )
            .await?
        {
            KernelSpecialResult::Completed(result) | KernelSpecialResult::Refused(result) => result,
            KernelSpecialResult::AccountingUnavailable { reason, .. } => {
                return Err(KernelError::ContextResolution(reason));
            }
        },
    )
}
#[tokio::test]
async fn actual_direct_constructor_keeps_native_identity_accounting_and_low_trust() {
    let (mut host, calls) = host("kernel-direct-owner");
    let result = execute(
        &mut host,
        KernelSpecialKind::Direct,
        &ToolUse {
            id: "actual-direct".into(),
            name: iteron_tools::DISPATCH_AGENT.into(),
            input: serde_json::json!({"task":"read the fixture"}),
        },
    )
    .await
    .unwrap();
    assert!(!result.is_error);
    assert_eq!(result.trust, Trust::Untrusted);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.ledger.provider_attempts, 1);
    assert_eq!(host.ledger.tool_calls, 1);
    let events = iteron_record::replay(host.rollout.path()).unwrap();
    let run = events
        .iter()
        .find_map(|event| match &event.kind {
            EventKind::SubagentFinishedV2 {
                sub_run, metrics, ..
            } => {
                assert_eq!(metrics.provider_attempts, 1);
                Some(sub_run.clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(run.starts_with("direct-"));
    assert!(events.iter().any(|event|matches!(&event.kind,EventKind::ToolDone {result,effect_id:Some(_),..} if result.trust==Trust::Untrusted)));
    assert!(host.parent_effects_known());
    let pending = events
        .iter()
        .position(|event| matches!(&event.kind, EventKind::ChildAccountingPendingV1 { .. }))
        .unwrap();
    let tool=events.iter().position(|event|matches!(&event.kind,EventKind::ToolDone {result,..} if result.tool_use_id=="actual-direct")).unwrap();
    let accounted = events
        .iter()
        .position(|event| matches!(&event.kind, EventKind::SubagentFinishedV2 { .. }))
        .unwrap();
    let resolved = events
        .iter()
        .position(|event| matches!(&event.kind, EventKind::ChildAccountingResolvedV1 { .. }))
        .unwrap();
    assert!(pending < tool && tool < accounted && accounted < resolved);
    let mut before = iteron_obs::Ledger::default();
    let mut replay = iteron_obs::pricing::PricingReplay::default();
    for event in &events[..=tool] {
        replay
            .observe(
                event,
                host.rollout.tenant(),
                host.rollout.run_id(),
                &mut before,
            )
            .unwrap();
    }
    assert!(!before.child_accounting_complete());
    for event in &events[tool + 1..] {
        replay
            .observe(
                event,
                host.rollout.tenant(),
                host.rollout.run_id(),
                &mut before,
            )
            .unwrap();
    }
    assert!(before.child_accounting_complete());
}
#[tokio::test]
async fn actual_plan_inspection_has_one_native_terminal_and_no_provider_io() {
    let (mut host, calls) = host("kernel-plan-owner");
    let result = execute(
        &mut host,
        KernelSpecialKind::Plan,
        &ToolUse {
            id: "actual-plan".into(),
            name: iteron_tools::UPDATE_PLAN.into(),
            input: serde_json::json!({"operation":"inspect"}),
        },
    )
    .await
    .unwrap();
    assert_eq!(result.trust, Trust::Untrusted);
    assert!(!result.is_error);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let events = iteron_record::replay(host.rollout.path()).unwrap();
    assert_eq!(events.iter().filter(|event|matches!(&event.kind,EventKind::ToolDone {tool:Some(tool),..} if tool==iteron_tools::UPDATE_PLAN)).count(),1);
    assert_eq!(host.ledger.tool_calls, 1);
}
#[cfg(feature = "script-workflows")]
#[tokio::test]
async fn native_two_child_workflow_merges_true_ledgers_under_one_parent_budget() {
    let (mut host, calls) = host("kernel-workflow-owner");
    host.budget.max_turns = 9;
    let result=execute(&mut host,KernelSpecialKind::Workflow,&ToolUse {id:"actual-script".into(),name:iteron_tools::WORKFLOW_TOOL.into(),input:serde_json::json!({"script":"return await parallel([() => agent('first'), () => agent('second')]);","background":true})}).await.unwrap();
    assert!(!result.is_error, "{}", result.content);
    assert_eq!(result.trust, Trust::Untrusted);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(host.ledger.provider_attempts, 2);
    assert_eq!(host.ledger.tool_calls, 1);
    let events = iteron_record::replay(host.rollout.path()).unwrap();
    assert_eq!(events.iter().filter(|event|matches!(&event.kind,EventKind::WorkflowV2 {event:iteron_protocol::WorkflowEvent::ChildFinished {metrics,..},..} if metrics.provider_attempts==1)).count(),2);
}

struct Waiting(tokio::sync::Notify);
#[async_trait::async_trait]
impl Provider for Waiting {
    fn provider_instance_id(&self) -> Option<&str> {
        Some("fixture-provider")
    }
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        self.0.notify_one();
        std::future::pending().await
    }
}
#[tokio::test]
async fn dropped_actual_direct_await_preserves_unresolved_physical_intent() {
    let (mut host, _) = host("kernel-direct-drop-owner");
    let provider = Arc::new(Waiting(tokio::sync::Notify::new()));
    host.record_operator_model_selection(
        provider.clone(),
        "fixture-provider".into(),
        "fixture-model".into(),
        String::new(),
        String::new(),
    )
    .unwrap();
    let call = ToolUse {
        id: "dropped-direct".into(),
        name: iteron_tools::DISPATCH_AGENT.into(),
        input: serde_json::json!({"task":"wait"}),
    };
    let mut execution = Box::pin(execute(&mut host, KernelSpecialKind::Direct, &call));
    tokio::select! {
        _=provider.0.notified()=>{},
        result=&mut execution=>panic!("actual provider did not remain running: {result:?}"),
        _=tokio::time::sleep(std::time::Duration::from_secs(5))=>panic!("actual provider was not entered"),
    }
    drop(execution);
    assert!(!host.parent_effects_known());
    let events = iteron_record::replay(host.rollout.path()).unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(&event.kind, EventKind::EffectIntent { .. }))
    );
    assert!(!events.iter().any(|event|matches!(&event.kind,EventKind::ToolDone {result,..} if result.tool_use_id=="dropped-direct")));
}

#[tokio::test]
async fn actual_known_child_still_seals_outer_terminal_when_accounting_admission_is_full() {
    let (mut host, calls) = host("kernel-accounting-pressure");
    let call = ToolUse {
        id: "known-at-capacity".into(),
        name: iteron_tools::DISPATCH_AGENT.into(),
        input: serde_json::json!({"task":"read"}),
    };
    let projection = host.turn_result_projection_budget(
        ContextBudgetInspection::from_policy(Default::default(), Default::default()),
        std::slice::from_ref(&call),
    );
    let (ports, output) =
        host.kernel_special_execution(TurnId(1), 0, KernelSpecialKind::Direct, projection);
    let crate::runtime::kernel_special_execution::KernelSpecialExecution {
        work,
        mut journal,
        mut control,
        failed_actions,
        hooks,
        ..
    } = ports;
    let events = output.events.clone();
    let workspace = journal.workspace().to_owned();
    let admitted = crate::runtime::kernel_tool_call::KernelToolCall::begin(
        &mut journal.tool(failed_actions),
        output,
        &workspace,
        TurnId(1),
        0,
        &call,
        Capability::CodeExecuting,
    )
    .unwrap();
    let effect = admitted.effect_id().clone();
    let crate::runtime::kernel_special_execution::KernelDispatchWork::Direct(work) = work else {
        unreachable!()
    };
    let completion = work
        .run(
            crate::runtime::direct_child_execution::DirectChildInvocation {
                turn: TurnId(1),
                index: 0,
                task: "read",
            },
            &mut journal,
            &mut control,
            &events,
            hooks,
        )
        .await
        .unwrap();
    for index in 0..64 {
        journal
            .begin_child_accounting(&iteron_protocol::EffectId(format!("retained-{index}")))
            .unwrap();
    }
    let (result, source) = completion.into_parts();
    let result = super::complete_known_special(
        &mut journal,
        failed_actions,
        admitted,
        super::tool_result(&call, result, Trust::Untrusted),
        super::KnownSpecialObservation {
            accounting: source,
            events: &events,
            turn: TurnId(1),
            effect: &effect,
        },
    )
    .unwrap();
    assert!(matches!(
        result,
        KernelSpecialResult::AccountingUnavailable { .. }
    ));
    drop(journal);
    drop(control);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.ledger.provider_attempts, 0);
    assert!(host.parent_effects_known());
    assert!(matches!(
        host.inference_budget_exhaustion(),
        Err(KernelError::ContextResolution(_))
    ));
    let events = iteron_record::replay(host.rollout.path()).unwrap();
    assert!(events.iter().any(|event|matches!(&event.kind,EventKind::ToolDone {effect_id:Some(_),result,..} if result.tool_use_id==call.id)));
    assert!(
        !events
            .iter()
            .any(|event| matches!(&event.kind, EventKind::EffectUnknown { .. }))
    );
}
