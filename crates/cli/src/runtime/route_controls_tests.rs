use super::*;
use iteron_provider::{
    CacheBreakpoint, CacheScope, ProviderControlCapabilities, ProviderRequestControls,
};
use std::sync::{Arc, Mutex};

struct CaptureRoute {
    id: &'static str,
    cache: bool,
    requests: Mutex<Vec<TurnRequest>>,
}

#[async_trait::async_trait]
impl Provider for CaptureRoute {
    fn provider_instance_id(&self) -> Option<&str> {
        Some(self.id)
    }

    fn control_capabilities(&self) -> ProviderControlCapabilities {
        let mut capabilities = ProviderControlCapabilities::default();
        if self.cache {
            capabilities
                .cache_breakpoints
                .insert(CacheBreakpoint::Rolling);
            capabilities.cache_scopes.insert(CacheScope::Session);
            capabilities.cache_ttl_seconds.insert(300);
            capabilities
                .service_tiers
                .insert(iteron_provider::ServiceTier::Priority);
        }
        capabilities
    }

    async fn turn(
        &self,
        request: &TurnRequest,
        _on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<iteron_provider::TurnResult, iteron_provider::ProviderError> {
        self.control_capabilities()
            .validate(&request.controls)
            .unwrap();
        self.requests.lock().unwrap().push(request.clone());
        Ok(iteron_provider::TurnResult {
            blocks: vec![Block::Text {
                text: "done".into(),
            }],
            stop_reason: iteron_protocol::StopReason::EndTurn,
            usage: iteron_provider::UsageReport::complete(iteron_protocol::Usage::default()),
        })
    }
}

fn route(id: &'static str, cache: bool) -> Arc<CaptureRoute> {
    Arc::new(CaptureRoute {
        id,
        cache,
        requests: Mutex::new(Vec::new()),
    })
}

fn agent_for_route(ws: &std::path::Path, source: Arc<CaptureRoute>) -> Agent {
    let rollout = Rollout::open(
        &ws.join(".iteron/runs"),
        &iteron_protocol::RunId("route-cache-hint".into()),
        iteron_protocol::TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        source,
        Registry::read_only(ws).unwrap(),
        rollout,
        "model-a".into(),
        "sys".into(),
        Budget {
            max_turns: 8,
            ..Budget::default()
        },
    );
    agent.workspace = ws.to_owned();
    super::gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent
}

fn switch(agent: &mut Agent, provider: Arc<CaptureRoute>, model: &str) -> Result<(), KernelError> {
    agent.record_operator_model_selection(
        provider.clone(),
        provider.id.into(),
        model.into(),
        format!("sha256:{}", "a".repeat(64)),
        format!("sha256:{}", "b".repeat(64)),
    )
}

#[tokio::test]
async fn model_switch_omits_optional_cache_hint_on_each_physical_request() {
    let ws = super::gate_integration_tests::temp_ws("route-cache-hint");
    let source = route("cache-source", true);
    let target = route("cache-target", false);
    let mut agent = agent_for_route(&ws, source.clone());
    let mut controls = ProviderRequestControls::default();
    controls.prompt_cache.breakpoint = CacheBreakpoint::Rolling;
    agent.set_provider_controls(controls).unwrap();
    switch(&mut agent, source.clone(), "model-a").unwrap();
    assert_eq!(agent.run("first").await.unwrap(), Outcome::Done);
    let checkpoint =
        serde_json::to_value(agent.tunables_checkpoint().unwrap().as_v2().unwrap()).unwrap();

    switch(&mut agent, target.clone(), "model-b").unwrap();
    assert_eq!(agent.follow_up("second").await.unwrap(), Outcome::Done);
    agent
        .summarize(&[Message::user_text("summarize this")], None)
        .await
        .unwrap();
    {
        let captured = target.requests.lock().unwrap();
        assert_eq!(
            captured.len(),
            2,
            "main and auxiliary requests both use target controls"
        );
        for request in captured.iter() {
            assert_eq!(
                request.controls.prompt_cache.breakpoint,
                CacheBreakpoint::None
            );
            assert!(
                !request.cache_system,
                "legacy bit must not re-enable unsupported breakpoints"
            );
        }
    }
    assert_eq!(
        agent.provider_controls, controls,
        "session preference remains immutable"
    );
    assert_eq!(
        serde_json::to_value(agent.tunables_checkpoint().unwrap().as_v2().unwrap()).unwrap(),
        checkpoint
    );

    switch(&mut agent, source.clone(), "model-a").unwrap();
    assert_eq!(agent.follow_up("third").await.unwrap(), Outcome::Done);
    let captured = source.requests.lock().unwrap();
    assert_eq!(captured.len(), 2);
    assert!(captured.iter().all(|request| request.cache_system
        && request.controls.prompt_cache.breakpoint == CacheBreakpoint::Rolling));
    drop(captured);
    drop(agent);
    std::fs::remove_dir_all(ws).ok();
}

#[test]
fn optional_cache_adaptation_preserves_other_control_refusals() {
    for ttl in [false, true] {
        let ws = super::gate_integration_tests::temp_ws("route-required-controls");
        let source = route("cache-source", true);
        let target = route("cache-target", false);
        let mut agent = agent_for_route(&ws, source.clone());
        let mut controls = ProviderRequestControls::default();
        controls.prompt_cache.breakpoint = CacheBreakpoint::Rolling;
        if ttl {
            controls.prompt_cache.ttl_seconds = 300;
        } else {
            controls.service_tier = iteron_provider::ServiceTier::Priority;
        }
        agent.set_provider_controls(controls).unwrap();
        let result = switch(&mut agent, target.clone(), "model-b");
        assert!(matches!(
            result,
            Err(KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                ..
            })
        ));
        assert_eq!(agent.model, "model-a");
        assert_eq!(agent.provider_controls, controls);
        assert!(target.requests.lock().unwrap().is_empty());
        drop(agent);
        std::fs::remove_dir_all(ws).ok();
    }
}

#[test]
fn resumed_controls_can_install_without_rewriting_the_cache_preference() {
    let ws = super::gate_integration_tests::temp_ws("route-resumed-cache-hint");
    let mut agent = agent_for_route(&ws, route("cache-target", false));
    let mut controls = ProviderRequestControls::default();
    controls.prompt_cache.breakpoint = CacheBreakpoint::Rolling;
    agent.set_provider_controls(controls).unwrap();
    assert_eq!(agent.provider_controls, controls);
    assert!(!agent.provider_cache_system_enabled());
    drop(agent);
    std::fs::remove_dir_all(ws).ok();
}
