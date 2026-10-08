use super::{RequestConfiguration, RequestContent, RequestPreparation};
use crate::runtime::context_runtime::ContextBudgetRecoveryGuard;
use crate::runtime::{Agent, DurableAppendFault, KernelError};
use iteron_ctx::{CompactionPolicy, ContextBudgetPolicy};
use iteron_protocol::{Block, Budget, EventKind, Message, Role, RunId, TenantId, TurnId};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
use iteron_record::Rollout;
use std::path::PathBuf;
use std::sync::Arc;

struct NeverDispatch;
#[async_trait::async_trait]
impl Provider for NeverDispatch {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("request preparation cannot dispatch a provider")
    }
}
fn fixture() -> (PathBuf, Agent, Vec<Message>) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "iteron-request-preparation-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let rollout = Rollout::open(
        &directory.join("runs"),
        &RunId("preparation".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        Arc::new(NeverDispatch),
        iteron_tools::Registry::read_only(&directory).unwrap(),
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
    agent.workspace = directory.clone();
    agent.context_budget_policy = ContextBudgetPolicy::for_usable_window(1_000_000, 64, 0);
    agent.context_budget_policy.transcript_tokens = 2_000;
    agent.compaction.enabled = true;
    agent.compaction.keep_recent = 1;
    agent.compaction.coverage_check = false;
    let mut messages = vec![Message::user_text("original operator task")];
    for _ in 0..4 {
        messages.push(Message {
            role: Role::Assistant,
            content: vec![Block::Text {
                text: "history ".repeat(4_000),
            }],
        });
    }
    messages.push(Message::user_text("continue"));
    for message in &messages {
        agent
            .emit_durable(
                TurnId(0),
                EventKind::Message {
                    message: message.clone(),
                },
            )
            .unwrap();
    }
    agent
        .transcript_state
        .replace_working(Some(messages.clone()));
    (directory, agent, messages)
}
fn preparation<'a>(agent: &mut Agent, messages: &'a mut Vec<Message>) -> RequestPreparation<'a> {
    RequestPreparation::new(
        RequestContent {
            system: "system".into(),
            messages: super::RequestMessages::Borrowed(messages),
            input_images: Vec::new(),
            tools: Vec::new().into(),
            max_tokens: 64,
        },
        32,
        Some(1_000_000),
        agent.request_accounting(),
        &mut agent.context_estimator,
    )
}
fn config() -> RequestConfiguration {
    RequestConfiguration {
        model: "actual-current-route".into(),
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: iteron_protocol::ReasoningEffort::Medium,
        controls: iteron_provider::ProviderRequestControls::default(),
    }
}

#[test]
fn actual_model_phase_writer_refusal_cannot_rearm_context_or_provider_admission() {
    let (directory, mut agent, mut messages) = fixture();
    agent.context_budget_policy.transcript_tokens = 1_000_000;
    let preparation = preparation(&mut agent, &mut messages);
    let mut owner = crate::runtime::request_admission::RequestAdmission::new(
        preparation,
        TurnId(7),
        Some(1_000_000),
        64,
    )
    .unwrap();
    let mut loop_state = crate::runtime::agent_loop::AgentLoopGuard::begin(TurnId(7));
    agent.fail_next_durable_append = Some(DurableAppendFault::BestEffort);
    let (journal, events) = agent.request_admission_ports(TurnId(7));
    assert!(matches!(
        owner.validate(journal, &events, &mut loop_state),
        Err(KernelError::Record(_))
    ));
    assert!(owner.request_gate().is_err());
    assert!(owner.control_passed().is_err());
    drop(owner);
    let path = agent.rollout.path().to_owned();
    drop(agent);
    let events = iteron_record::replay(&path).unwrap();
    assert!(
        !events
            .iter()
            .any(|event| matches!(&event.kind, EventKind::EffectIntent { .. }))
    );
    assert!(!events.iter().any(|event| matches!(
        &event.kind,
        EventKind::Phase {
            phase: iteron_protocol::Phase::Model
        }
    )));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn context_gate_denial_keeps_actual_request_undispatched_and_without_admitted_context() {
    let (directory, mut agent, mut messages) = fixture();
    agent.context_budget_policy.transcript_tokens = 1_000_000;
    let preparation = preparation(&mut agent, &mut messages);
    let mut owner = crate::runtime::request_admission::RequestAdmission::new(
        preparation,
        TurnId(7),
        Some(1_000_000),
        64,
    )
    .unwrap();
    let mut loop_state = crate::runtime::agent_loop::AgentLoopGuard::begin(TurnId(7));
    let (journal, events) = agent.request_admission_ports(TurnId(7));
    owner.validate(journal, &events, &mut loop_state).unwrap();
    owner.request_gate().unwrap();
    assert!(matches!(
        owner.gate_completed(crate::runtime::hooks::HookDecision::Deny(
            "actual context gate denial".into()
        )),
        Err(KernelError::ContextResolution(_))
    ));
    assert!(owner.request_gate().is_err());
    assert!(owner.control_passed().is_err());
    assert!(agent.context_ledgers.snapshot().ledgers.is_empty());
    drop(owner);
    let path = agent.rollout.path().to_owned();
    drop(agent);
    assert!(
        !iteron_record::replay(&path)
            .unwrap()
            .iter()
            .any(|event| matches!(&event.kind, EventKind::EffectIntent { .. }))
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn real_writer_refusal_keeps_original_transcript_and_candidate_unusable() {
    let (directory, mut agent, mut messages) = fixture();
    let original = messages.clone();
    let mut owner = preparation(&mut agent, &mut messages);
    let mut guard = ContextBudgetRecoveryGuard::default();
    assert!(
        owner
            .recovery_request(&agent.compaction, false, &mut guard)
            .is_some()
    );
    owner.authorize_recovery(&agent.compaction, true);
    assert_eq!(
        owner
            .assess_summary(
                "bounded handoff",
                true,
                &agent.compaction,
                &agent.context_estimator,
                agent.request_accounting()
            )
            .unwrap(),
        None
    );
    agent.fail_next_durable_append = Some(DurableAppendFault::Compaction);
    let receipt = agent.record_compaction_committed(
        TurnId(0),
        &original,
        owner.plan().unwrap(),
        "bounded handoff",
        "component_budget_recovery",
        false,
    );
    assert!(matches!(receipt, Err(KernelError::Record(_))));
    assert!(agent.record_failed);
    assert!(!agent.compaction_state.compacted());
    assert_eq!(
        serde_json::to_value(&owner.request().messages).unwrap(),
        serde_json::to_value(&original).unwrap()
    );
    assert_eq!(
        serde_json::to_value(agent.transcript_state.working()).unwrap(),
        serde_json::to_value(Some(&original)).unwrap()
    );
    assert!(owner.validate().is_err());
    // A new candidate cannot be installed without the receipt that the real writer refused.
    assert!(owner.into_request(config()).is_err());
    let path = agent.rollout.path().to_owned();
    drop(agent);
    let reopened = Rollout::open(
        path.parent().unwrap(),
        &RunId("preparation".into()),
        TenantId::default(),
    )
    .unwrap();
    let events = iteron_record::replay(reopened.path()).unwrap();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, EventKind::Compaction { .. }))
    );
    let retained = events
        .into_iter()
        .filter_map(|event| match event.kind {
            EventKind::Message { message } => Some(message),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        serde_json::to_value(&retained).unwrap(),
        serde_json::to_value(&original).unwrap()
    );
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn confirmed_seed_installs_exact_candidate_then_replay_recovers_it() {
    let (directory, mut agent, mut messages) = fixture();
    let mut owner = preparation(&mut agent, &mut messages);
    let mut guard = ContextBudgetRecoveryGuard::default();
    assert!(
        owner
            .recovery_request(&agent.compaction, false, &mut guard)
            .is_some()
    );
    owner.authorize_recovery(&agent.compaction, true);
    assert!(
        owner
            .assess_summary(
                "bounded handoff",
                true,
                &agent.compaction,
                &agent.context_estimator,
                agent.request_accounting()
            )
            .unwrap()
            .is_none()
    );
    let receipt = agent
        .record_compaction_committed(
            TurnId(0),
            &owner.request().messages,
            owner.plan().unwrap(),
            "bounded handoff",
            "component_budget_recovery",
            false,
        )
        .unwrap();
    assert!(
        owner
            .commit_candidate(receipt, &mut agent.context_estimator)
            .unwrap()
            .is_some()
    );
    assert!(owner.settle_recovery(&mut guard).is_none());
    owner.validate().unwrap();
    let (request, policy_cap) = owner.into_request(config()).unwrap();
    assert_eq!(policy_cap, 32);
    assert_eq!(request.max_tokens, 64);
    assert_eq!(request.model, "actual-current-route");
    assert_eq!(
        serde_json::to_value(&request.messages).unwrap(),
        serde_json::to_value(&messages).unwrap()
    );
    let path = agent.rollout.path().to_owned();
    drop(agent);
    let reopened = Rollout::open(
        path.parent().unwrap(),
        &RunId("preparation".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut replayed = Vec::new();
    for event in iteron_record::replay(reopened.path()).unwrap() {
        match event.kind {
            EventKind::Message { message } => replayed.push(message),
            EventKind::Compaction { messages: seed } => {
                replayed = iteron_ctx::replay_compaction(replayed, seed)
            }
            _ => {}
        }
    }
    assert_eq!(
        serde_json::to_value(&replayed).unwrap(),
        serde_json::to_value(&request.messages).unwrap()
    );
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn uncovered_summary_closes_component_bridge_without_recursive_provider_spend() {
    let (directory, mut agent, mut messages) = fixture();
    let mut owner = preparation(&mut agent, &mut messages);
    let mut guard = ContextBudgetRecoveryGuard::default();
    assert!(
        owner
            .recovery_request(&agent.compaction, true, &mut guard)
            .is_some()
    );
    owner.authorize_recovery(&agent.compaction, true);
    assert_eq!(
        owner
            .assess_summary(
                "unproven",
                false,
                &agent.compaction,
                &agent.context_estimator,
                agent.request_accounting()
            )
            .unwrap(),
        Some("summary_coverage_missing")
    );
    assert!(owner.settle_recovery(&mut guard).is_some());
    assert!(owner.validate().is_err());
    drop(owner);
    let mut next = preparation(&mut agent, &mut messages);
    let mut policy = CompactionPolicy::default();
    policy.enabled = true;
    policy.keep_recent = 1;
    assert!(next.recovery_request(&policy, true, &mut guard).is_none());
    drop(next);
    drop(agent);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn actual_route_rebind_rechecks_output_headroom_and_keeps_original_policy_request() {
    let (directory, mut agent, _) = fixture();
    let mut messages = vec![Message::user_text(
        "bounded request after auxiliary route change",
    )];
    agent.context_estimator.invalidate_transcript();
    let mut owner = preparation(&mut agent, &mut messages);
    owner.bind_route_budget(Some(400), 512).unwrap();
    let refusal = owner
        .window_refusal()
        .expect("actual new route output cannot fit");
    assert!(matches!(
        refusal,
        KernelError::ContextWindowExceeded {
            reserved_output_tokens: 512,
            ..
        }
    ));
    assert!(owner.validate().is_err());
    // A later native route whose true output fits may be rebound before validation. This changes
    // the serialized physical cap, never the separate original caller policy commitment.
    owner.bind_route_budget(Some(400), 16).unwrap();
    owner.validate().unwrap();
    assert!(owner.bind_route_budget(Some(1_000_000), 64).is_err());
    let (request, policy) = owner.into_request(config()).unwrap();
    assert_eq!(request.max_tokens, 16);
    assert_eq!(policy, 32);
    drop(agent);
    let _ = std::fs::remove_dir_all(directory);
}

struct RecoveryObservedProvider {
    calls: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl Provider for RecoveryObservedProvider {
    fn physical_output_token_ceiling(
        &self,
        budget: iteron_provider::output_ceiling::ProviderOutputBudget<'_>,
    ) -> Result<Option<u32>, ProviderError> {
        Ok(Some(budget.requested_max_tokens))
    }
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("recovery must cross actual observed serialization")
    }
    async fn turn_observed(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
        observer: &dyn iteron_provider::request_capture::ProviderRequestObserver,
    ) -> Result<TurnResult, ProviderError> {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "model":request.model,"messages":request.messages,"system":request.system,
            "max_tokens":request.max_tokens,
        }))
        .unwrap();
        observer
            .prepared(iteron_provider::request_capture::ProviderWireRequest {
                adapter: iteron_provider::AdapterKind::OpenAiCompatibleChat,
                method: "POST",
                endpoint: "https://request-recovery-fixture.invalid/v1",
                content_type: "application/json",
                body: &bytes,
                serialized_output_tokens: request.max_tokens,
                request,
            })
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        observer
            .dispatching()
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let text = "Preserved operator task and current bounded continuation.";
        on_item(StreamItem::TextDelta(text.into()));
        Ok(TurnResult {
            blocks: vec![Block::Text { text: text.into() }],
            stop_reason: iteron_protocol::StopReason::EndTurn,
            usage: iteron_provider::UsageReport::complete(iteron_protocol::Usage::default()),
        })
    }
}

#[tokio::test]
async fn real_recovery_summary_cannot_replace_transcript_after_its_writer_refuses() {
    let (directory, mut agent, messages) = fixture();
    let provider = Arc::new(RecoveryObservedProvider {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    agent.provider = provider.clone();
    agent
        .transcript_state
        .replace_restored(Some(messages.clone()));
    agent.fail_next_durable_append = Some(DurableAppendFault::Compaction);
    assert!(matches!(agent.run("").await, Err(KernelError::Record(_))));
    assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        serde_json::to_value(agent.transcript_state.working().as_ref().unwrap()).unwrap(),
        serde_json::to_value(&messages).unwrap()
    );
    assert!(!agent.compaction_state.compacted());
    let run = agent.rollout.run_id().clone();
    let store = agent.rollout.path().parent().unwrap().to_path_buf();
    drop(agent);
    let reopened = Rollout::open_existing(&store, &run, TenantId::default()).unwrap();
    let rows = iteron_record::replay(reopened.path()).unwrap();
    assert!(
        !rows
            .iter()
            .any(|event| matches!(event.kind, EventKind::Compaction { .. }))
    );
    assert_eq!(
        rows.iter()
            .filter(
                |event| matches!(&event.kind,EventKind::EffectDone{tool,..} if tool=="provider")
            )
            .count(),
        1
    );
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn real_recovery_publishes_seed_before_the_main_request_and_retains_it_on_reopen() {
    let (directory, mut agent, messages) = fixture();
    let provider = Arc::new(RecoveryObservedProvider {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    agent.provider = provider.clone();
    agent.transcript_state.replace_restored(Some(messages));
    assert_eq!(agent.run("").await.unwrap(), crate::runtime::Outcome::Done);
    assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(agent.compaction_state.compacted());
    let run = agent.rollout.run_id().clone();
    let store = agent.rollout.path().parent().unwrap().to_path_buf();
    drop(agent);
    let reopened = Rollout::open_existing(&store, &run, TenantId::default()).unwrap();
    let rows = iteron_record::replay(reopened.path()).unwrap();
    let compacted = rows
        .iter()
        .position(|event| matches!(event.kind, EventKind::Compaction { .. }))
        .unwrap();
    let provider_intents = rows
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            matches!(&event.kind,EventKind::EffectIntent{tool,..} if tool=="provider")
                .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(provider_intents.len(), 2);
    assert!(provider_intents[0] < compacted && compacted < provider_intents[1]);
    assert_eq!(
        rows.iter()
            .filter(
                |event| matches!(&event.kind,EventKind::EffectDone{tool,..} if tool=="provider")
            )
            .count(),
        2
    );
    assert!(
        rows.iter()
            .any(|event| matches!(&event.kind,EventKind::Done{outcome} if outcome=="Done"))
    );
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

include!("compaction_coverage_error_tests.rs");
