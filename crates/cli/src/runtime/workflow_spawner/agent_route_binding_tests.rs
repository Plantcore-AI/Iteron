use super::*;
use iteron_agents::{AgentEngineOrigin, AgentEngineParentSource};
use iteron_protocol::PricingRoute;
use iteron_provider::{ProviderError, StreamItem, TurnRequest, TurnResult};
use std::sync::atomic::{AtomicUsize, Ordering};

struct NativeProvider {
    id: &'static str,
    requests: AtomicUsize,
}
#[async_trait::async_trait]
impl Provider for NativeProvider {
    fn provider_instance_id(&self) -> Option<&str> {
        Some(self.id)
    }
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        panic!("native route construction must not perform provider IO")
    }
}
fn origin() -> AgentEngineOrigin {
    AgentEngineOrigin::DirectSubagent {
        parent: AgentEngineParentSource {
            tenant: "tenant".into(),
            run: "parent".into(),
            provider_scope_sha256: crate::runtime::persistent_provider_budget::provider_scope_for(
                &TenantId("tenant".into()),
                &RunId("parent".into()),
            ),
        },
    }
}
fn fixture(
    label: &str,
) -> (
    PathBuf,
    KernelSpawnerContext,
    Arc<NativeProvider>,
    Arc<NativeProvider>,
) {
    let root = crate::runtime::gate_integration_tests::temp_ws(label);
    let primary = Arc::new(NativeProvider {
        id: "primary",
        requests: AtomicUsize::new(0),
    });
    let alternate = Arc::new(NativeProvider {
        id: "alternate",
        requests: AtomicUsize::new(0),
    });
    let mut cx = KernelSpawnerContext::new(
        primary.clone(),
        "model-primary".into(),
        "primary".into(),
        "a".repeat(64),
        "b".repeat(64),
        root.clone(),
        root.join("runs"),
        TenantId("tenant".into()),
        "parent".into(),
        "workflow".into(),
    );
    cx.model_context_window = Some(24_000);
    cx.model_max_output_tokens = Some(4_096);
    cx.fallback_provider_routes
        .push(super::super::GovernedProviderRoute::new(
            alternate.clone(),
            PricingRoute {
                provider_id: "alternate".into(),
                model_id: "model-alternate".into(),
                catalog_digest: "c".repeat(64),
                capability_digest: "d".repeat(64),
            },
            Some(false),
            Some(true),
            Some(12_000),
            Some(2_000),
            None,
        ));
    tests::pin_context(&root, &mut cx);
    (root, cx, primary, alternate)
}
fn request(model: &str) -> AgentCall {
    AgentCall {
        prompt: "inspect".into(),
        label: None,
        phase: None,
        model: Some(model.into()),
        effort: Some(Effort::Low),
        agent_type: Some("generic".into()),
        schema: None,
        cancel: Default::default(),
    }
}
#[test]
fn actual_child_uses_held_native_provider_route_and_its_caps_without_io() {
    let (root, cx, primary, alternate) = fixture("native-child-model-bound");
    let alternate_trait: Arc<dyn Provider> = alternate.clone();
    let expected_window = cx.model_context_window.map(|parent| parent.min(12_000));
    let spawner = KernelSpawner::new(cx);
    let binding = spawner
        .prepare_engine_execution(
            &super::super::persistent_agents::AgentEngineRequest {
                profile: Some("generic".into()),
                model: Some("model-alternate".into()),
                effort: Some(Effort::Low),
            },
            origin(),
        )
        .unwrap();
    assert_eq!(binding.provider_id, "alternate");
    assert_eq!(binding.catalog_digest, "c".repeat(64));
    let child = spawner
        .build_child_in_mode(
            &request("model-alternate"),
            0,
            None,
            false,
            Some(&binding),
            None,
        )
        .unwrap();
    assert!(Arc::ptr_eq(&child.provider, &alternate_trait));
    assert_eq!(child.model, "model-alternate");
    assert_eq!(child.model_context_window, expected_window);
    assert!(
        child
            .model_max_output_tokens
            .is_some_and(|cap| cap <= 2_000)
    );
    assert_eq!(child.effort, Effort::Low);
    let selected = child.provider_selection.selected().unwrap();
    assert_eq!(selected.route.provider_id, "alternate");
    assert_eq!(selected.route.capability_digest, "d".repeat(64));
    assert!(
        child
            .provider_governor
            .as_ref()
            .unwrap()
            .supports_route("alternate:model-alternate")
    );
    let path = child.rollout.path().to_owned();
    drop(child);
    assert!(
        iteron_record::replay(&path)
            .unwrap()
            .iter()
            .any(|event| matches!(&event.kind,
        iteron_protocol::EventKind::ModelSelected { provider_id, model_id, .. }
            if provider_id == "alternate" && model_id == "model-alternate"))
    );
    assert_eq!(primary.requests.load(Ordering::SeqCst), 0);
    assert_eq!(alternate.requests.load(Ordering::SeqCst), 0);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn unavailable_or_ambiguous_model_and_missing_governor_binding_cannot_mint_execution() {
    let (root, cx, primary, alternate) = fixture("native-child-model-refusals");
    let mut spawner = KernelSpawner::new(cx);
    let proposal = super::super::persistent_agents::AgentEngineRequest {
        profile: None,
        model: Some("unresolved".into()),
        effort: None,
    };
    assert!(
        spawner
            .prepare_engine_execution(&proposal, origin())
            .is_err()
    );
    let mut proposal = proposal;
    proposal.model = Some("model-alternate".into());
    let mut other = spawner.cx.fallback_provider_routes[0].clone();
    other.route.provider_id = "ambiguous".into();
    spawner.cx.fallback_provider_routes.push(other);
    assert!(
        spawner
            .prepare_engine_execution(&proposal, origin())
            .is_err()
    );
    spawner.cx.fallback_provider_routes.pop();
    let governor = spawner.cx.provider_governor.as_ref().unwrap();
    assert!(governor.unregister_idle_route("alternate:model-alternate"));
    assert!(
        spawner
            .prepare_engine_execution(&proposal, origin())
            .is_err()
    );
    assert!(!root.join("runs/subagents").exists());
    assert_eq!(primary.requests.load(Ordering::SeqCst), 0);
    assert_eq!(alternate.requests.load(Ordering::SeqCst), 0);
    std::fs::remove_dir_all(root).unwrap();
}
