//! Resident bootstrap integration: no user-configurable path can grant managed delegation.
use super::*;
use crate::config::McpServerConfig;
use crate::mcp::McpRuntimeControl;
use crate::runtime_tunables::effective_mcp::{
    EffectiveMcpSettings, McpCapabilityExposure, McpDiscoveryMode, McpOAuthLifecyclePolicy,
    McpTransportSelection,
};

fn configured_gateway(registry: &mut iteron_tools::Registry, url: &str) -> McpRuntimeControl {
    let config: McpServerConfig = serde_json::from_value(serde_json::json!({
        "name": "plantcore-run-gateway",
        "transport": "http",
        "url": url,
        "header_env": {"Authorization": "PLANTCORE_RUN_GATEWAY_AUTHORIZATION"},
    }))
    .unwrap();
    let runtime = crate::mcp::register_configured_servers(
        registry,
        std::slice::from_ref(&config),
        &["PLANTCORE_RUN_GATEWAY_AUTHORIZATION".into()],
    )
    .unwrap();
    runtime
        .configure(
            EffectiveMcpSettings {
                transport: McpTransportSelection::from_servers(std::slice::from_ref(&config)),
                oauth: McpOAuthLifecyclePolicy::disabled_fixture(),
                reconnect: iteron_mcp::reconnect::ReconnectPolicy::new(1, 1, 1).unwrap(),
                deadlines: iteron_mcp::McpDeadlinePolicy::default(),
                result: iteron_mcp::McpResultPolicy::new(
                    128,
                    4096,
                    iteron_mcp::McpSpillCleanup::SessionEnd,
                )
                .unwrap(),
            },
            McpCapabilityExposure {
                resource_discovery: McpDiscoveryMode::Lazy,
                prompt_discovery: McpDiscoveryMode::Lazy,
                resource_tool_ids: [
                    "plantcore-run-gateway__resources_list".into(),
                    "plantcore-run-gateway__resources_read".into(),
                ]
                .into_iter()
                .collect(),
                prompt_tool_ids: [
                    "plantcore-run-gateway__prompts_list".into(),
                    "plantcore-run-gateway__prompts_get".into(),
                ]
                .into_iter()
                .collect(),
                plugin_binding_ids: BTreeSet::new(),
                server_binding_ids: [config.runtime_binding_id().unwrap()].into_iter().collect(),
                max_visible_bytes: 128,
            },
        )
        .unwrap();
    runtime
}

#[test]
fn managed_gateway_bootstrap_installs_delegation_only_after_runtime_validation() {
    let workspace = std::env::temp_dir().join(format!(
        "iteron-managed-bootstrap-{}-{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&workspace).unwrap();
    let mut registry = iteron_tools::Registry::coding_agent(&workspace).unwrap();
    let mcp = configured_gateway(&mut registry, MCP_URL);
    let rollout = iteron_record::Rollout::open(
        &workspace.join("runs"),
        &iteron_protocol::RunId("run-1".into()),
        iteron_protocol::TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        std::sync::Arc::new(super::tests::IdentifiedTestProvider),
        registry,
        rollout,
        "qwen".into(),
        "startup".into(),
        iteron_protocol::Budget::default(),
    );
    agent.workspace = "/workspace/work".into();
    crate::app_server::fixtures::pin_test_tunables(&mut agent, false, "plantcore", "qwen");
    agent.install_mcp_runtime(mcp.clone()).unwrap();
    let mut payload = super::tests::payload();
    payload.engine.external_mcp_posture = ExternalMcpPosture::RunGateway;
    payload.run_gateway.external_mcp_posture = ExternalMcpPosture::RunGateway;
    payload.run_gateway.catalog_snapshot_revision = "test-catalog".into();
    payload.run_gateway.catalog_snapshot_digest_sha256 = HexSha256::digest(b"test-catalog");
    let mut admission = PlantcoreAdmission::required("https://provider.example/v1".into());
    let gate = admission.dispatch_gate().unwrap();
    agent.install_plantcore_dispatch_gate(gate.clone());
    agent.bypass_permissions = true;
    assert!(
        admission
            .admit(payload.clone(), &mut agent, Some(&mcp))
            .is_err()
    );
    assert_eq!(
        gate.submit_if_admitted(|| Ok::<_, ()>(())),
        Err("run_not_admitted")
    );
    agent.bypass_permissions = false;
    let accepted = admission
        .admit(payload.clone(), &mut agent, Some(&mcp))
        .unwrap();
    assert_eq!(accepted.run_id, payload.run_id);
    assert_eq!(gate.submit_if_admitted(|| Ok::<_, ()>(())), Ok(Ok(())));
    // Replay is idempotent, and neither replays nor ordinary MCP config can re-delegate.
    assert_eq!(
        admission.admit(payload, &mut agent, Some(&mcp)).unwrap(),
        accepted
    );
    assert!(mcp.delegate_plantcore_gateway(gate.clone()).is_err());
    assert!(!agent.bypass_permissions);
    assert_eq!(
        agent.permission_rules().cap_rule(Capability::CodeExecuting),
        Some(Verdict::Deny)
    );
    gate.terminal();
    drop(agent);
    std::fs::remove_dir_all(workspace).unwrap();
}
