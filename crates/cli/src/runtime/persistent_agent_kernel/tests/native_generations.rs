//! Actual current-route admission, live resident retention and exact native journal recovery.
use super::parent_turn::main_runtime;
use super::{
    AgentActor, AgentCommandV1, AgentControlPort, Arc, KernelPersistentRuntime, ProviderFixture,
    Workspace, budget, setup, until,
};
use crate::runtime::persistent_agents::AgentEngineRequest;
use crate::runtime::persistent_native_generations::NativeGenerations;
use iteron_agents::{AgentEngineOrigin, AgentEngineParentSource};
use iteron_protocol::agent_control::{AgentIdV1, AgentStateV1};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Capability, PricingRoute, RunId, TurnId};
use std::time::{Duration, Instant};
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
    let (host, runtime, _, control) = setup(&workspace, old.clone(), false);
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
    let old_execution = host
        .shared
        .controller
        .lock()
        .unwrap()
        .ordinary_native_child(first)
        .unwrap()
        .unwrap();
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
    let new_execution = host
        .shared
        .controller
        .lock()
        .unwrap()
        .ordinary_native_child(second)
        .unwrap()
        .unwrap();
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
