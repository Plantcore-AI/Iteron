//! Real Main runtime and retained child journeys through the same host/controller.
use super::{
    AgentActor, AgentCommandV1, AgentControlPort, AgentIdV1, AgentStateV1, Arc, Block,
    KernelPersistentRuntime, Ordering, ProviderFixture, Store, Workspace, setup, setup_with_store,
    spawn, until,
};
use crate::runtime::Agent;
use iteron_protocol::{EventKind, Outcome};

fn main_runtime(runtime: &KernelPersistentRuntime, control: Arc<dyn AgentControlPort>) -> Agent {
    let root = control.host_limits().unwrap().root;
    let call = iteron_workflow::AgentCall {
        prompt: String::new(),
        label: Some("Main fixture".into()),
        phase: None,
        model: None,
        effort: None,
        agent_type: Some("generic".into()),
        schema: None,
        cancel: Default::default(),
    };
    // This is the caller's actual Agent instance. It is never inserted into the resident map and
    // never executed by host.dispatch_ready for root identity.
    let mut main = runtime
        .spawner
        .lock()
        .unwrap()
        .build_persistent_child(&call, &root, None)
        .unwrap();
    if let Some(fixture) = &runtime.fixture {
        fixture(&mut main);
    }
    main.persistent_agents = Some(control);
    main
}
fn text(messages: &[iteron_protocol::Message]) -> String {
    messages
        .iter()
        .flat_map(|message| &message.content)
        .filter_map(|block| match block {
            Block::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn actual_main_and_child_exchange_consumed_inputs_without_a_second_root_resident() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, control) = setup(&workspace, provider.clone(), false);
    let mut main = main_runtime(&runtime, control);
    let child = spawn(&host, "child first task");
    until(|| host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle).await;
    let from_child = host
        .command(
            AgentActor::Agent(child),
            "to-main",
            AgentCommandV1::SendMessage {
                agent_id: AgentIdV1(1),
                text: "untrusted child-to-main data".into(),
            },
        )
        .unwrap()
        .message_id
        .unwrap();
    assert!(matches!(
        host.message(AgentActor::Operator, from_child)
            .unwrap()
            .state,
        iteron_protocol::agent_control::AgentMessageStateV1::Accepted
    ));
    assert_eq!(
        main.run("actual Main operator instruction").await.unwrap(),
        Outcome::Done
    );
    assert!(
        provider
            .texts
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .contains("untrusted child-to-main data")
    );
    assert!(matches!(
        host.message(AgentActor::Operator, from_child)
            .unwrap()
            .state,
        iteron_protocol::agent_control::AgentMessageStateV1::Consumed { .. }
    ));
    assert!(
        !runtime
            .residents
            .lock()
            .unwrap()
            .contains_key(&AgentIdV1(1))
    );
    assert_eq!(main.observed_trust, iteron_protocol::Trust::Untrusted);
    assert!(text(main.working_set.as_ref().unwrap()).contains("actual Main operator instruction"));
    assert!(
        main.working_set
            .as_ref()
            .unwrap()
            .iter()
            .any(|message| message.role == iteron_protocol::Role::User
                && text(std::slice::from_ref(message))
                    .contains("actual Main operator instruction")
                && text(std::slice::from_ref(message)).contains("Main thread task source sha256:")
                && text(std::slice::from_ref(message)).contains("untrusted child-to-main data"))
    );
    let to_child = host
        .command(
            AgentActor::Agent(AgentIdV1(1)),
            "to-child",
            AgentCommandV1::SendMessage {
                agent_id: child,
                text: "main-to-child followup data".into(),
            },
        )
        .unwrap()
        .message_id
        .unwrap();
    host.command(
        AgentActor::Operator,
        "child-followup",
        AgentCommandV1::FollowupTask {
            agent_id: child,
            text: "continue the retained child".into(),
        },
    )
    .unwrap();
    until(|| {
        matches!(
            host.message(AgentActor::Operator, to_child).unwrap().state,
            iteron_protocol::agent_control::AgentMessageStateV1::Consumed { .. }
        ) && host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle
    })
    .await;
    assert!(
        provider
            .texts
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .contains("main-to-child followup data")
    );
}

#[tokio::test]
async fn actual_main_mailbox_barrier_failure_has_zero_provider_io_and_no_consumed_claim() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, control) = setup_with_store(
        &workspace,
        provider.clone(),
        false,
        Store {
            fail_consumed: true,
            ..Store::default()
        },
    );
    let mut main = main_runtime(&runtime, control);
    assert!(main.run("root receipt barrier fixture").await.is_err());
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
    let view = host.inspect(AgentActor::Operator, AgentIdV1(1)).unwrap();
    assert_eq!(view.reserved.tokens, 0);
    assert_eq!(view.reserved.cost_microusd, 0);
    assert!(!matches!(
        host.message(
            AgentActor::Operator,
            iteron_protocol::agent_control::AgentMessageIdV1(1)
        )
        .unwrap()
        .state,
        iteron_protocol::agent_control::AgentMessageStateV1::Consumed { .. }
    ));
    assert!(crate::runtime::replay_scoped_rollout(main.rollout.path()).unwrap().iter().any(|event|
        matches!(&event.event.kind, EventKind::EffectFailed { provider_route_attempt: Some(accounting), .. }
            if accounting.usage == iteron_protocol::ProviderRouteUsageTruth::NotDispatched)));
}

#[tokio::test]
async fn actual_root_interrupt_stops_the_current_agent_tool_before_epoch_settlement() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, settled, control) = setup(&workspace, provider.clone(), true);
    let mut main = main_runtime(&runtime, control);
    let worker = tokio::spawn(async move {
        let result = main.run("block-tool").await;
        (main, result)
    });
    until(|| provider.tool_started.load(Ordering::SeqCst) == 1).await;
    let epoch = host
        .inspect(AgentActor::Operator, AgentIdV1(1))
        .unwrap()
        .state
        .epoch()
        .unwrap();
    host.command(
        AgentActor::Operator,
        "stop-main",
        AgentCommandV1::Interrupt {
            agent_id: AgentIdV1(1),
            epoch,
        },
    )
    .unwrap();
    let (main, result) = tokio::time::timeout(std::time::Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Ok(Outcome::Interrupted)));
    assert_eq!(settled.load(Ordering::SeqCst), 1);
    assert!(main.persistent_mailbox.is_none());
    assert!(!matches!(
        host.inspect(AgentActor::Operator, AgentIdV1(1))
            .unwrap()
            .state,
        AgentStateV1::Running { .. } | AgentStateV1::Interrupting { .. }
    ));
    assert!(
        !runtime
            .residents
            .lock()
            .unwrap()
            .contains_key(&AgentIdV1(1))
    );
}

#[tokio::test]
async fn known_main_terminal_append_refusal_retains_proof_and_retries_once_before_next_epoch() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let fault = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (host, runtime, _, control) = setup_with_store(
        &workspace,
        provider.clone(),
        false,
        Store {
            fail_parent_terminal: Some(fault.clone()),
            ..Store::default()
        },
    );
    let mut main = main_runtime(&runtime, control);
    assert!(main.run("first actual Main task").await.is_err());
    assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
    assert!(!fault.load(Ordering::SeqCst));
    assert!(matches!(
        host.inspect(AgentActor::Operator, AgentIdV1(1))
            .unwrap()
            .state,
        AgentStateV1::Running { .. }
    ));
    main.stage_follow_up_transcript().await.unwrap();
    assert_eq!(
        main.run("next actual Main task").await.unwrap(),
        Outcome::Done
    );
    let view = host.inspect(AgentActor::Operator, AgentIdV1(1)).unwrap();
    assert_eq!(view.state, AgentStateV1::Idle);
    assert_eq!(view.usage.turns, 2); // The retained terminal proof cannot charge twice.
    assert_eq!(view.usage.tokens, 4);
    assert_eq!(provider.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn failure_after_main_epoch_claim_quarantines_and_releases_the_live_stop_slot() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, control) = setup_with_store(
        &workspace,
        provider.clone(),
        false,
        Store {
            fail_parent_delivery: true,
            ..Store::default()
        },
    );
    let mut main = main_runtime(&runtime, control);
    assert!(main.run("never dispatched Main source").await.is_err());
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
    assert!(main.persistent_mailbox.is_none());
    assert!(matches!(
        host.inspect(AgentActor::Operator, AgentIdV1(1))
            .unwrap()
            .state,
        AgentStateV1::RecoveryRequired { .. }
    ));
    assert!(matches!(
        main.run("must not resurrect the old epoch").await,
        Err(crate::runtime::KernelError::AgentControl(
            iteron_agents::ControllerError::RecoveryRequired
        ))
    ));
}
