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
            messages,
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
    assert!(!agent.compacted_in_run);
    assert_eq!(
        serde_json::to_value(&owner.request().messages).unwrap(),
        serde_json::to_value(&original).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&agent.transcript_state.working()).unwrap(),
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
    let (directory, mut agent, mut messages) = fixture();
    messages = vec![Message::user_text(
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
