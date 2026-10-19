//! Real Main runtime and retained child journeys through the same host/controller.
use super::{
    AgentActor, AgentCommandV1, AgentControlPort, AgentIdV1, AgentStateV1, Arc, Block,
    KernelPersistentRuntime, Ordering, ProviderFixture, Store, Workspace, resident_observation,
    setup, setup_with_store, spawn, until_observed, until_resident_observed,
};
use crate::runtime::Agent;
use iteron_protocol::{EventKind, Outcome};

pub(super) fn main_runtime(
    runtime: &KernelPersistentRuntime,
    control: Arc<dyn AgentControlPort>,
) -> Agent {
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
        .generations
        .lock()
        .unwrap()
        .bootstrap()
        .build_persistent_child(&call, &root, None, None)
        .unwrap();
    if let Some(fixture) = &runtime.fixture {
        fixture(&mut main, root.agent_id);
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
    until_resident_observed(&host, child, &provider, || {
        host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle
    })
    .await;
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
    assert!(
        text(main.transcript_state.working().as_ref().unwrap())
            .contains("actual Main operator instruction")
    );
    assert!(
        main.transcript_state
            .working()
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
    until_resident_observed(&host, child, &provider, || {
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
    until_observed(
        || provider.tool_started.load(Ordering::SeqCst) == 1,
        || resident_observation(&host, AgentIdV1(1), &provider),
    )
    .await;
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

#[tokio::test]
async fn actual_engine_profile_preserves_effort_parent_and_native_cost_attribution() {
    use crate::runtime::persistent_agents::AgentEngineRequest;
    use iteron_agents::{AgentEngineOrigin, AgentEngineParentSource, AgentWorkflowChildBinding};
    use iteron_protocol::Effort;
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, control) = setup(&workspace, provider.clone(), false);
    let mut main = main_runtime(&runtime, control.clone());
    main.run("bind actual Main physical provider scope")
        .await
        .unwrap();
    main.kernel_controller_scope(
        iteron_protocol::TurnId(1),
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
    .unwrap();
    let parent = AgentEngineParentSource {
        tenant: main.rollout.tenant().0.clone(),
        run: main.rollout.run_id().0.clone(),
        provider_scope_sha256: main.provider_scope(),
    };
    let bound = control
        .prepare_engine_child(
            AgentActor::Agent(AgentIdV1(1)),
            &AgentEngineRequest {
                profile: Some("generic".into()),
                model: None,
                effort: Some(Effort::Low),
            },
            AgentEngineOrigin::DirectSubagent {
                parent: parent.clone(),
            },
        )
        .unwrap();
    assert_eq!(bound.effort, Effort::Low);
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let admitted = control
        .spawn_engine_child(
            AgentActor::Agent(AgentIdV1(1)),
            "actual-profile-child",
            AgentCommandV1::Spawn {
                parent_id: AgentIdV1(1),
                label: "bound profile".into(),
                task: "actual profile task".into(),
                capabilities: iteron_protocol::capability_set::CapabilitySet::only(
                    iteron_protocol::Capability::ReadOnly,
                ),
                budget: super::budget(4),
                write_paths: vec![],
            },
            AgentWorkflowChildBinding {
                workflow_id: "actual-profile-child".into(),
                node_id: 1,
                attempt: 1,
                input_digest: "a".repeat(64),
                deadline_unix_ms: now + 10_000,
                execution: Some(bound),
            },
        )
        .unwrap();
    until_resident_observed(&host, admitted.claim.assigned_agent, &provider, || {
        host.engine_child_completion(&admitted.claim)
            .unwrap()
            .is_some()
    })
    .await;
    let child = runtime
        .residents
        .lock()
        .unwrap()
        .get(&admitted.claim.assigned_agent)
        .unwrap()
        .clone();
    let child = child.lock().await;
    assert_eq!(child.effort, Effort::Low);
    assert_eq!(
        child.projection_attribution,
        Some(iteron_protocol::CostAttribution::DirectSubagent {
            parent_run_id: parent.run,
            sub_run: child.rollout.run_id().0.clone(),
        })
    );
    assert!(
        host.engine_child_completion(&admitted.claim)
            .unwrap()
            .unwrap()
            .effects_known
    );
    let before = provider.requests.load(Ordering::SeqCst);
    assert!(
        control
            .prepare_engine_child(
                AgentActor::Agent(AgentIdV1(1)),
                &AgentEngineRequest {
                    profile: Some("unavailable-profile".into()),
                    model: None,
                    effort: None
                },
                AgentEngineOrigin::DirectSubagent {
                    parent: AgentEngineParentSource {
                        tenant: main.rollout.tenant().0.clone(),
                        run: main.rollout.run_id().0.clone(),
                        provider_scope_sha256: main.provider_scope(),
                    }
                },
            )
            .is_err()
    );
    assert_eq!(provider.requests.load(Ordering::SeqCst), before);
}

fn unsupported_main_image() -> iteron_protocol::ContentSegments {
    iteron_protocol::ContentSegments::new(vec![
        iteron_protocol::ContentSegment::Text {
            text: "unsupported image must not reach the model".into(),
        },
        iteron_protocol::ContentSegment::Image {
            image: iteron_protocol::ImageContent::new(
                iteron_protocol::ImageMediaType::Png,
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
            )
            .unwrap(),
        },
    ])
    .unwrap()
}

#[tokio::test]
async fn actual_installed_main_retries_a_preworking_refusal_without_reconstructing_its_owners() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, control) = setup(&workspace, provider.clone(), false);
    let mut main = main_runtime(&runtime, control.clone());
    assert!(matches!(
        main.run_content(&unsupported_main_image()).await,
        Err(crate::runtime::KernelError::InvalidSubmission(reason))
            if reason == crate::runtime::context_runtime::IMAGE_INPUT_UNSUPPORTED_REASON
    ));
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
    assert!(main.transcript_state.working().is_none());
    // Main's admitted controller task consumes one conservative lifetime slot even when
    // unsupported media is refused before physical provider dispatch. A retry never refunds it.
    assert_eq!(
        host.inspect(AgentActor::Operator, AgentIdV1(1))
            .unwrap()
            .usage
            .turns,
        1
    );
    assert_eq!(
        main.transcript_state.live_owner(&main.rollout),
        Some(AgentIdV1(1))
    );
    let budget = main.budget.clone();
    let card = main.provider_selection.card().cloned();
    let turn = main.current_turn_id();
    let pin = main
        .tunables_pin
        .as_ref()
        .unwrap()
        .resolution_digest_sha256()
        .to_owned();
    let bytes = std::fs::read(main.rollout.path()).unwrap();
    assert!(matches!(
        main.set_resume(vec![iteron_protocol::Message::user_text(
            "another projection"
        )]),
        Err(crate::runtime::KernelError::AgentControl(
            iteron_agents::ControllerError::Invalid(_)
        ))
    ));
    assert_eq!(std::fs::read(main.rollout.path()).unwrap(), bytes);
    assert_eq!(
        host.inspect(AgentActor::Operator, AgentIdV1(1))
            .unwrap()
            .state,
        AgentStateV1::Idle
    );
    assert_eq!(
        main.follow_up("actual same Main retry").await.unwrap(),
        Outcome::Done
    );
    assert!(main.current_turn_id().0 > turn.0);
    assert_eq!(main.budget, budget);
    assert_eq!(main.provider_selection.card(), card.as_ref());
    assert_eq!(
        main.tunables_pin
            .as_ref()
            .unwrap()
            .resolution_digest_sha256(),
        pin
    );
    assert!(Arc::ptr_eq(
        main.persistent_agents.as_ref().unwrap(),
        &control
    ));
    assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
    let view = host.inspect(AgentActor::Operator, AgentIdV1(1)).unwrap();
    assert_eq!(view.state, AgentStateV1::Idle);
    assert_eq!(view.usage.turns, 2);
    assert!(
        !runtime
            .residents
            .lock()
            .unwrap()
            .contains_key(&AgentIdV1(1))
    );
    let events = iteron_record::replay(main.rollout.path()).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::RunStart { .. }))
            .count(),
        1
    );
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "provider")).count(), 1);
    assert!(events.iter().any(|event| matches!(&event.kind, EventKind::Message { message } | EventKind::MessageV2 { message, .. }
        if text(std::slice::from_ref(message)).contains("actual same Main retry"))));
}

#[tokio::test]
async fn installed_main_staging_requires_a_live_witness_and_refuses_unconfirmed_effects() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (_, runtime, _, control) = setup(&workspace, provider.clone(), false);
    let mut main = main_runtime(&runtime, control);
    assert!(main.transcript_state.live_owner(&main.rollout).is_none());
    let before = std::fs::read(main.rollout.path()).unwrap();
    assert!(matches!(
        main.follow_up("cold instance is not a live staging proof")
            .await,
        Err(crate::runtime::KernelError::AgentControl(
            iteron_agents::ControllerError::Invalid(_)
        ))
    ));
    assert_eq!(std::fs::read(main.rollout.path()).unwrap(), before);
    assert!(matches!(
        main.run_content(&unsupported_main_image()).await,
        Err(crate::runtime::KernelError::InvalidSubmission(_))
    ));
    let turn = main.current_turn_id();
    // A real admitted journal intent with no terminal is uncertainty even if this fixture did
    // not dispatch its executor. Recovery must retain it, never create a successful result.
    let call = iteron_protocol::ToolUse {
        id: "unclosed-live-main-effect".into(),
        name: "read_file".into(),
        input: serde_json::json!({"path":"pending.txt"}),
    };
    let _ticket = main
        .open_tool_call_effect(turn, 0, &call, iteron_protocol::Capability::ReadOnly)
        .unwrap();
    main.effect_journal.adopt_journal();
    assert!(matches!(
        main.follow_up("must not bypass unknown physical history")
            .await,
        Err(crate::runtime::KernelError::UnknownEffects { .. })
            | Err(crate::runtime::KernelError::AgentControl(
                iteron_agents::ControllerError::RecoveryRequired
            ))
    ));
    assert_eq!(main.current_turn_id(), turn);
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
    assert!(!main.parent_effects_known());
    let events = iteron_record::replay(main.rollout.path()).unwrap();
    assert!(events.iter().any(
        |event| matches!(&event.kind, EventKind::EffectUnknown { tool, .. } if tool == "read_file")
    ));
    assert!(!events.iter().any(
        |event| matches!(&event.kind, EventKind::EffectDone { tool, .. } if tool == "read_file")
    ));
    assert!(!events.iter().any(
        |event| matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "provider")
    ));
}
