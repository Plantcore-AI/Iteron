//! Actual current-route admission, live resident retention and exact native journal recovery.
use super::parent_turn::main_runtime;
use super::{
    AgentActor, AgentCommandV1, AgentControlPort, Arc, ProviderFixture, Store, Workspace, budget,
    setup, setup_with_store, until,
};
use crate::runtime::persistent_agents::AgentEngineRequest;
use crate::runtime::persistent_native_generations::NativeGenerations;
use iteron_agents::{AgentEngineOrigin, AgentEngineParentSource};
use iteron_protocol::agent_control::{AgentIdV1, AgentStateV1};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Capability, PricingRoute, RunId, TurnId};
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn committed_native_execution(
    committed: &Mutex<Option<iteron_agents::AgentControllerSnapshot>>,
    id: AgentIdV1,
) -> iteron_agents::AgentEngineExecution {
    // Read the actual submitted journal value, rather than opening the host's mutable owner.
    let value = serde_json::to_value(committed.lock().unwrap().as_ref().unwrap()).unwrap();
    serde_json::from_value(value["agents"][id.0.to_string()]["native_execution"].clone()).unwrap()
}
fn command(label: &str) -> AgentCommandV1 {
    AgentCommandV1::Spawn {
        parent_id: AgentIdV1(1),
        label: label.into(),
        task: label.into(),
        capabilities: CapabilitySet::only(Capability::ReadOnly),
        budget: iteron_protocol::agent_control::AgentBudgetV1 {
            cost_microusd: 100_000,
            ..budget(2)
        },
        write_paths: vec![],
    }
}
fn pricing(routes: &[PricingRoute]) -> Arc<dyn iteron_obs::PricingPort> {
    let key = [42; 32];
    let cards = routes
        .iter()
        .map(|route| {
            let signed = iteron_obs::sign_rate_card(
                iteron_protocol::RateCard {
                    version: iteron_protocol::PricingVersion::V1,
                    route: route.clone(),
                    provenance: "native generation fixture".into(),
                    issued_at_unix_secs: 1,
                    expires_at_unix_secs: u64::MAX,
                    rates: iteron_protocol::TokenRateCard {
                        input_microusd_per_million: 0,
                        output_microusd_per_million: 0,
                        cache_creation_microusd_per_million: 0,
                        cache_read_microusd_per_million: 0,
                        thinking_microusd_per_million: 0,
                    },
                },
                "fixture-pricing",
                key,
            )
            .unwrap();
            (signed, iteron_obs::HmacPricingKey::from_bytes(key))
        })
        .collect();
    Arc::new(iteron_obs::HmacPricingAuthority::new(cards).unwrap())
}
#[tokio::test]
async fn actual_model_switch_mints_new_spawn_binding_and_old_resident_retains_transport() {
    let workspace = Workspace::new();
    let old = Arc::new(ProviderFixture::default());
    let new = Arc::new(ProviderFixture::default());
    let committed = Arc::new(Mutex::new(None));
    let (host, runtime, _, control) = setup_with_store(
        &workspace,
        old.clone(),
        false,
        Store {
            committed_snapshot: Some(committed.clone()),
            ..Default::default()
        },
    );
    let mut main = main_runtime(&runtime, control.clone());
    main.run("bind real root source").await.unwrap();
    main.kernel_controller_scope(TurnId(1), Instant::now() + Duration::from_secs(10))
        .unwrap();
    let old_route = main.provider_selection.selected().unwrap().route.clone();
    let first = host
        .command(
            AgentActor::Operator,
            "old-native-child",
            command("old native child"),
        )
        .unwrap()
        .agent_id;
    until(|| host.inspect(AgentActor::Operator, first).unwrap().state == AgentStateV1::Idle).await;
    let old_execution = committed_native_execution(&committed, first);
    let new_route = PricingRoute {
        model_id: "test-new-model".into(),
        ..old_route.clone()
    };
    main.provider_selection
        .set_pricing_port(pricing(&[old_route.clone(), new_route.clone()]));
    main.record_operator_model_selection(
        new.clone(),
        new_route.provider_id.clone(),
        new_route.model_id.clone(),
        new_route.catalog_digest.clone(),
        new_route.capability_digest.clone(),
    )
    .unwrap();
    main.refresh_persistent_native_context(TurnId(2)).unwrap();
    let second = host
        .command(
            AgentActor::Operator,
            "new-native-child",
            command("new native child"),
        )
        .unwrap()
        .agent_id;
    until(|| host.inspect(AgentActor::Operator, second).unwrap().state == AgentStateV1::Idle).await;
    let new_execution = committed_native_execution(&committed, second);
    assert_ne!(old_execution.native_context, new_execution.native_context);
    assert_eq!(new_execution.model_id, "test-new-model");
    let old_child = runtime
        .residents
        .lock()
        .unwrap()
        .get(&first)
        .unwrap()
        .clone();
    let new_child = runtime
        .residents
        .lock()
        .unwrap()
        .get(&second)
        .unwrap()
        .clone();
    let old_provider: Arc<dyn iteron_provider::Provider> = old.clone();
    let new_provider: Arc<dyn iteron_provider::Provider> = new.clone();
    assert!(Arc::ptr_eq(&old_child.lock().await.provider, &old_provider));
    assert!(Arc::ptr_eq(&new_child.lock().await.provider, &new_provider));
    host.command(
        AgentActor::Operator,
        "retained-old-epoch",
        AgentCommandV1::FollowupTask {
            agent_id: first,
            text: "old resident next epoch".into(),
        },
    )
    .unwrap();
    until(|| host.inspect(AgentActor::Operator, first).unwrap().state == AgentStateV1::Idle).await;
    assert_eq!(old_child.lock().await.model, old_route.model_id);
    // The real exact WAL reference reconstructs an earlier context only through a held native
    // route. A string in the completion/profile can never create a new transport.
    let mut current = main.kernel_spawner_context(&new_route, "persistent-agents");
    let namespace = runtime
        .generations
        .lock()
        .unwrap()
        .bootstrap()
        .persistent_namespace()
        .0
        .to_owned();
    current.parent_run_id = namespace;
    current
        .fallback_provider_routes
        .push(crate::runtime::GovernedProviderRoute::new(
            old_provider.clone(),
            old_route.clone(),
            None,
            Some(true),
            Some(100_000),
            Some(1000),
            None,
        ));
    let mut reopened = NativeGenerations::new(current);
    let restored = reopened.for_execution(Some(&old_execution)).unwrap();
    assert!(restored.same_native_primary(&old_provider));
    let mut forged = old_execution.clone();
    forged.native_context.as_mut().unwrap().sequence += 1;
    assert!(reopened.for_execution(Some(&forged)).is_err());
    assert!(
        host.command(
            AgentActor::Operator,
            "old-native-child",
            command("old native child")
        )
        .unwrap()
        .replayed
    );
    assert_eq!(runtime.residents.lock().unwrap().len(), 2);
}
#[tokio::test]
async fn context_source_is_actual_scope_and_same_description_new_transport_is_a_new_publication() {
    let workspace = Workspace::new();
    let old = Arc::new(ProviderFixture::default());
    let (_, runtime, _, control) = setup(&workspace, old, false);
    let mut main = main_runtime(&runtime, control.clone());
    main.run("bind generation source").await.unwrap();
    main.refresh_persistent_native_context(TurnId(1)).unwrap();
    let source = AgentEngineParentSource {
        tenant: main.rollout.tenant().0.clone(),
        run: main.rollout.run_id().0.clone(),
        provider_scope_sha256: main.provider_scope(),
    };
    let request = AgentEngineRequest {
        profile: Some("generic".into()),
        model: None,
        effort: None,
    };
    let prior = control
        .prepare_engine_child(
            AgentActor::Agent(AgentIdV1(1)),
            &request,
            AgentEngineOrigin::DirectSubagent {
                parent: source.clone(),
            },
        )
        .unwrap();
    let route = main.provider_selection.selected().unwrap().route.clone();
    let other = Arc::new(ProviderFixture::default());
    main.record_operator_model_selection(
        other,
        route.provider_id.clone(),
        route.model_id.clone(),
        route.catalog_digest.clone(),
        route.capability_digest.clone(),
    )
    .unwrap();
    main.refresh_persistent_native_context(TurnId(2)).unwrap();
    let current = control
        .prepare_engine_child(
            AgentActor::Agent(AgentIdV1(1)),
            &request,
            AgentEngineOrigin::DirectSubagent {
                parent: source.clone(),
            },
        )
        .unwrap();
    assert_ne!(prior.native_context, current.native_context);
    let mut foreign = source;
    foreign.run = "another real-scope name".into();
    let context = main.kernel_spawner_context(&route, "persistent-agents");
    assert!(
        control
            .native_context_reference(AgentActor::Agent(AgentIdV1(1)), &foreign, &context)
            .is_err()
    );
    assert_eq!(runtime.residents.lock().unwrap().len(), 0);
    let events = crate::runtime::replay_scoped_rollout(main.rollout.path()).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|row| matches!(
                &row.event.kind,
                iteron_protocol::EventKind::NativeChildContextCapturedV1 { .. }
            ))
            .count(),
        2
    );
    assert_eq!(
        main.rollout.run_id(),
        &RunId(current.origin.parent().run.clone())
    );
}

#[tokio::test]
async fn actual_nested_bare_spawn_inherits_resident_model_rules_and_exact_child_wal() {
    let workspace = Workspace::new();
    let old = Arc::new(ProviderFixture::default());
    let current = Arc::new(ProviderFixture::default());
    let committed = Arc::new(Mutex::new(None));
    let (host, runtime, _, control) = setup_with_store(
        &workspace,
        old,
        false,
        Store {
            committed_snapshot: Some(committed.clone()),
            ..Default::default()
        },
    );
    let mut main = main_runtime(&runtime, control.clone());
    main.run("bind actual nested Main").await.unwrap();
    let old_route = main.provider_selection.selected().unwrap().route.clone();
    let route = PricingRoute {
        model_id: "nested-current-model".into(),
        ..old_route.clone()
    };
    main.provider_selection
        .set_pricing_port(pricing(&[old_route, route.clone()]));
    main.record_operator_model_selection(
        current.clone(),
        route.provider_id.clone(),
        route.model_id.clone(),
        route.catalog_digest.clone(),
        route.capability_digest.clone(),
    )
    .unwrap();
    let mut rules = main.permission_rules().clone();
    rules.set_tool("web_search", iteron_protocol::Verdict::Deny);
    main.transition_permission_rules(rules, iteron_protocol::RuntimePolicySource::Operator)
        .unwrap();
    main.refresh_persistent_native_context(TurnId(1)).unwrap();
    let first = host
        .command(
            AgentActor::Operator,
            "actual-nested-parent",
            command("nested parent"),
        )
        .unwrap()
        .agent_id;
    until(|| host.inspect(AgentActor::Operator, first).unwrap().state == AgentStateV1::Idle).await;
    let parent = runtime
        .residents
        .lock()
        .unwrap()
        .get(&first)
        .unwrap()
        .clone();
    let parent = parent.lock().await;
    assert!(
        parent.persistent_agents.is_none(),
        "no strong resident/host cycle"
    );
    let run = parent.rollout.run_id().clone();
    let path = parent.rollout.path().to_owned();
    let parent_rules = parent.permission_rules().clone();
    drop(parent);
    let nested = AgentCommandV1::Spawn {
        parent_id: first,
        label: "actual nested child".into(),
        task: "nested child response".into(),
        capabilities: CapabilitySet::only(Capability::ReadOnly),
        budget: iteron_protocol::agent_control::AgentBudgetV1 {
            turns: 1,
            tokens: 250_000,
            cost_microusd: 50_000,
            wall_ms: 5_000,
        },
        write_paths: vec![],
    };
    // The same real actor-bound host port used by the installed agent_task handler.
    let grandchild = host
        .command(AgentActor::Agent(first), "actual-grandchild", nested)
        .unwrap()
        .agent_id;
    until(|| {
        host.inspect(AgentActor::Operator, grandchild)
            .unwrap()
            .state
            == AgentStateV1::Idle
    })
    .await;
    let binding = committed_native_execution(&committed, grandchild);
    let reference = binding.native_context.as_ref().unwrap();
    assert_eq!(reference.run, run.0);
    assert_eq!(binding.model_id, route.model_id);
    let bytes = std::fs::read(&path).unwrap();
    let captured = iteron_record::native_child_context::read_reference(&bytes, reference).unwrap();
    assert_eq!(captured.permission_rules, parent_rules);
    assert_eq!(captured.route, route);
    let resident = runtime
        .residents
        .lock()
        .unwrap()
        .get(&grandchild)
        .unwrap()
        .clone();
    let grandchild = resident.lock().await;
    let provider: Arc<dyn iteron_provider::Provider> = current;
    assert!(Arc::ptr_eq(&grandchild.provider, &provider));
    assert_eq!(grandchild.permission_rules(), &parent_rules);
}

#[tokio::test]
async fn actual_scope_publications_do_not_consume_sixteen_historical_generation_slots() {
    let workspace = Workspace::new();
    let (_, runtime, _, control) = setup(&workspace, Arc::new(ProviderFixture::default()), false);
    let mut main = main_runtime(&runtime, control);
    main.run("bind actual quota fixture").await.unwrap();
    let route = main.provider_selection.selected().unwrap().route.clone();
    let template = main.kernel_spawner_context(&route, "persistent-agents");
    let mut generations = NativeGenerations::new(template.clone());
    let state = workspace.0.join("quota-records");
    std::fs::create_dir(&state).unwrap();
    let mut first_writer = None;
    let mut first_source = None;
    let mut first_context = None;
    for ordinal in 1..=64 {
        let run = RunId(format!("actual-native-quota-{ordinal}"));
        let mut writer =
            iteron_record::Rollout::open(&state, &run, template.tenant.clone()).unwrap();
        let mut context = template.clone();
        context.parent_run_id = run.0.clone();
        let source = AgentEngineParentSource {
            tenant: template.tenant.0.clone(),
            run: run.0,
            provider_scope_sha256: iteron_protocol::agent_cohort::provider_scope(
                writer.tenant(),
                writer.run_id(),
            ),
        };
        assert!(
            generations
                .reference(AgentIdV1(ordinal), &source, &context)
                .unwrap()
                .is_none()
        );
        publish_quota(
            &mut generations,
            AgentIdV1(ordinal),
            &mut writer,
            context.clone(),
            &source,
        );
        if ordinal == 1 {
            first_writer = Some(writer);
            first_source = Some(source);
            first_context = Some(context);
        }
    }
    let mut writer = first_writer.unwrap();
    let source = first_source.unwrap();
    let mut context = first_context.unwrap();
    // Different actual transport objects, with the same description, must retain distinct
    // durable publications. These are historical generations rather than new scoped owners.
    for _ in 0..16 {
        context.provider = Arc::new(ProviderFixture::default());
        assert!(
            generations
                .reference(AgentIdV1(1), &source, &context)
                .unwrap()
                .is_none()
        );
        publish_quota(
            &mut generations,
            AgentIdV1(1),
            &mut writer,
            context.clone(),
            &source,
        );
    }
    context.provider = Arc::new(ProviderFixture::default());
    assert!(matches!(
        generations.reference(AgentIdV1(1), &source, &context),
        Err(iteron_agents::ControllerError::Capacity)
    ));
    assert!(matches!(
        generations.default_child(AgentIdV1(1), false),
        Err(iteron_agents::ControllerError::RecoveryRequired)
    ));
    let absent = NativeGenerations::new(template);
    assert!(matches!(
        absent.default_child(AgentIdV1(2), false),
        Err(iteron_agents::ControllerError::RecoveryRequired)
    ));
    drop(writer);
}

fn publish_quota(
    generations: &mut NativeGenerations,
    owner: AgentIdV1,
    writer: &mut iteron_record::Rollout,
    context: crate::runtime::workflow_spawner::KernelSpawnerContext,
    source: &AgentEngineParentSource,
) {
    let publication = crate::runtime::workflow_spawner::native_context::capture(
        &context,
        source,
        writer.next_sequence().0,
    )
    .unwrap();
    let sequence = writer
        .append(&iteron_protocol::Event {
            seq: iteron_protocol::Seq::ZERO,
            turn: TurnId(0),
            kind: iteron_protocol::EventKind::NativeChildContextCapturedV1 {
                context: publication.clone(),
            },
        })
        .unwrap();
    let reference = iteron_protocol::native_child_context::NativeChildContextRefV1 {
        generation_sha256: publication.generation_sha256.clone(),
        tenant: source.tenant.clone(),
        run: source.run.clone(),
        sequence: sequence.0,
    };
    let bytes = std::fs::read(writer.path()).unwrap();
    assert_eq!(
        iteron_record::native_child_context::read_reference(&bytes, &reference).unwrap(),
        publication
    );
    generations
        .install(owner, context, source, &publication, reference)
        .unwrap();
}
