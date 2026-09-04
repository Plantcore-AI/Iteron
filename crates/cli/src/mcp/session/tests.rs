use super::*;
use iteron_protocol::ToolUse;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

fn fixture(marker: &Path) -> McpServerConfig {
    let script = concat!(
        "printf 'spawned' > \"$1\"; ",
        "IFS= read -r discover; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}'; ",
        "IFS= read -r initialize; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{},\"resources\":{},\"prompts\":{}}}}'; ",
        "IFS= read -r initialized; ",
        "IFS= read -r list; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[{\"name\":\"echo\",\"description\":\"fixture\",\"inputSchema\":{\"type\":\"object\"}}]}}'; ",
        "IFS= read -r call; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"pong\"}]}}'; ",
        "exec sleep 60"
    );
    McpServerConfig {
        name: "alpha".into(),
        origin: crate::config::McpServerOrigin::default(),
        transport: McpTransportConfig::Stdio,
        command: Some("/bin/bash".into()),
        args: vec![
            "-c".into(),
            script.into(),
            "mcp-session-fixture".into(),
            marker.to_string_lossy().into_owned(),
        ],
        env_names: Vec::new(),
        url: None,
        header_env: BTreeMap::new(),
        oauth: None,
        tools: iteron_mcp::McpToolFilter::default(),
        policy: iteron_mcp::McpServerPolicy::default(),
    }
}

fn http_fixture(oauth: Option<crate::config::McpOAuthConfig>) -> McpServerConfig {
    McpServerConfig {
        name: "alpha".into(),
        origin: crate::config::McpServerOrigin::default(),
        transport: McpTransportConfig::Http,
        command: None,
        args: Vec::new(),
        env_names: Vec::new(),
        url: Some("https://example.invalid/mcp".into()),
        header_env: BTreeMap::new(),
        oauth,
        tools: iteron_mcp::McpToolFilter::default(),
        policy: iteron_mcp::McpServerPolicy::default(),
    }
}

fn modern_fixture(marker: &Path) -> McpServerConfig {
    let script = concat!(
        "printf 'spawned' > \"$1\"; ",
        "IFS= read -r discover; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{\"tools\":{}}}}'; ",
        "IFS= read -r list; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"echo\",\"description\":\"fixture\",\"inputSchema\":{\"type\":\"object\"}}]}}'; ",
        "IFS= read -r call; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"pong\"}]}}'; ",
        "exec sleep 60"
    );
    McpServerConfig {
        args: vec![
            "-c".into(),
            script.into(),
            "mcp-modern-session-fixture".into(),
            marker.to_string_lossy().into_owned(),
        ],
        ..fixture(marker)
    }
}

fn modern_mrtr_fixture(marker: &Path, resumed_request: &Path) -> McpServerConfig {
    let script = concat!(
        "printf 'spawned' > \"$1\"; ",
        "IFS= read -r discover; ",
        "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{\"tools\":{}}}}'; ",
        "IFS= read -r list; ",
        "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"profile\",\"description\":\"fixture\",\"inputSchema\":{\"type\":\"object\"}}]}}'; ",
        "IFS= read -r call; ",
        "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resultType\":\"input_required\",\"requestState\":\"round-1\",\"inputRequests\":{\"profile-input\":{\"method\":\"elicitation/create\",\"params\":{\"message\":\"Choose a profile name\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}}}}}}'; ",
        "IFS= read -r resumed; ",
        "printf '%s' \"$resumed\" > \"$2\"; ",
        "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"profile accepted\"}]}}'; ",
        "exec sleep 60"
    );
    McpServerConfig {
        args: vec![
            "-c".into(),
            script.into(),
            "mcp-modern-mrtr-fixture".into(),
            marker.to_string_lossy().into_owned(),
            resumed_request.to_string_lossy().into_owned(),
        ],
        ..fixture(marker)
    }
}

fn stateful_2025_fixture(marker: &Path) -> McpServerConfig {
    let script = concat!(
        "printf 'spawned' > \"$1\"; ",
        "IFS= read -r discover; ",
        "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}'; ",
        "IFS= read -r initialize; ",
        "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{\"tools\":{}}}}'; ",
        "IFS= read -r initialized; ",
        "IFS= read -r list; ",
        "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[{\"name\":\"echo\",\"description\":\"fixture\",\"inputSchema\":{\"type\":\"object\"}}]}}'; ",
        "IFS= read -r call; ",
        "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"pong\"}]}}'; ",
        "exec sleep 60"
    );
    McpServerConfig {
        args: vec![
            "-c".into(),
            script.into(),
            "mcp-stateful-2025-fixture".into(),
            marker.to_string_lossy().into_owned(),
        ],
        ..fixture(marker)
    }
}

struct RecordingMrtrHandler {
    states: Arc<StdMutex<Vec<Option<String>>>>,
}

impl iteron_mcp::McpMrtrHandler for RecordingMrtrHandler {
    fn request<'a>(
        &'a self,
        _server_name: &'a str,
        _tool_name: &'a str,
        request_state: Option<&'a str>,
        requests: Vec<iteron_mcp::McpInputRequest>,
    ) -> iteron_mcp::McpFuture<'a, iteron_mcp::McpInputDecision> {
        self.states
            .lock()
            .unwrap()
            .push(request_state.map(str::to_owned));
        Box::pin(async move {
            Ok(iteron_mcp::McpInputDecision::Approve(
                requests
                    .into_iter()
                    .map(|request| (request.id().to_owned(), serde_json::json!({"name":"Alice"})))
                    .collect(),
            ))
        })
    }
}

fn bearer_oauth() -> crate::config::McpOAuthConfig {
    crate::config::McpOAuthConfig {
        access_token_env: Some("MCP_ACCESS_TOKEN".into()),
        expires_at_env: None,
        refresh_url: None,
        refresh_token_env: None,
        client_id: None,
        client_secret_env: None,
        resource: None,
        scopes: Vec::new(),
        registration: crate::config::OAuthClientRegistration::Auto,
        revoke_url: None,
    }
}

fn refresh_oauth() -> crate::config::McpOAuthConfig {
    crate::config::McpOAuthConfig {
        access_token_env: Some("MCP_ACCESS_TOKEN".into()),
        expires_at_env: Some("MCP_ACCESS_EXPIRES".into()),
        refresh_url: Some("https://example.invalid/oauth/refresh".into()),
        refresh_token_env: Some("MCP_REFRESH_TOKEN".into()),
        client_id: Some("core-test".into()),
        client_secret_env: Some("MCP_CLIENT_SECRET".into()),
        resource: None,
        scopes: Vec::new(),
        registration: crate::config::OAuthClientRegistration::Auto,
        revoke_url: Some("https://example.invalid/oauth/revoke".into()),
    }
}

fn settings(cleanup: iteron_mcp::McpSpillCleanup) -> EffectiveMcpSettings {
    EffectiveMcpSettings {
        transport: crate::runtime_tunables::effective_mcp::McpTransportSelection::stdio_fixture(),
        oauth: crate::runtime_tunables::effective_mcp::McpOAuthLifecyclePolicy::disabled_fixture(),
        reconnect: iteron_mcp::reconnect::ReconnectPolicy::new(1, 1, 1).unwrap(),
        deadlines: iteron_mcp::McpDeadlinePolicy::default(),
        result: iteron_mcp::McpResultPolicy::new(128, 4096, cleanup).unwrap(),
    }
}

fn exposure(name: &str) -> McpCapabilityExposure {
    use crate::runtime_tunables::effective_mcp::McpDiscoveryMode;
    McpCapabilityExposure {
        resource_discovery: McpDiscoveryMode::Lazy,
        prompt_discovery: McpDiscoveryMode::Lazy,
        resource_tool_ids: [
            format!("{name}__resources_list"),
            format!("{name}__resources_read"),
        ]
        .into_iter()
        .collect(),
        prompt_tool_ids: [
            format!("{name}__prompts_list"),
            format!("{name}__prompts_get"),
        ]
        .into_iter()
        .collect(),
        plugin_binding_ids: std::collections::BTreeSet::new(),
        server_binding_ids: std::collections::BTreeSet::new(),
        max_visible_bytes: 128,
    }
}

fn bound_exposure(config: &McpServerConfig) -> McpCapabilityExposure {
    let mut exposure = exposure(&config.name);
    exposure
        .server_binding_ids
        .insert(config.runtime_binding_id().unwrap());
    exposure
}

fn plugin_exposure(
    live: &McpServerConfig,
    plugin_id: &str,
    version: &str,
) -> McpCapabilityExposure {
    let mut declared = live.clone();
    declared.origin = crate::config::McpServerOrigin::plugin_fixture(plugin_id, version);
    let mut exposure = bound_exposure(&declared);
    exposure.plugin_binding_ids.insert(
        declared
            .origin
            .plugin_binding_id(&declared.name)
            .unwrap()
            .unwrap(),
    );
    exposure
}

#[test]
fn operator_json_cannot_mint_plugin_origin() {
    let operator: crate::config::McpServerConfig = serde_json::from_value(json!({
        "name": "operator",
        "command": "server",
        "args": []
    }))
    .unwrap();
    assert_eq!(operator.origin.label(), "operator");
    assert!(
        serde_json::from_value::<crate::config::McpServerConfig>(json!({
            "name": "forged",
            "command": "server",
            "args": [],
            "origin": {
                "plugin_id": "docs-pack",
                "version": "1.2.3"
            }
        }))
        .is_err(),
        "the serde-skipped provenance field must remain an unknown field under deny_unknown_fields"
    );
}

fn marker() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    std::env::temp_dir().join(format!(
        "iteron-cli-mcp-lazy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn empty_runtime_preflight_is_pure_and_configuration_retains_the_exact_policy() {
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime = McpRuntimeControl::register(&mut registry, &[], &[]).unwrap();
    let policy = EffectiveMcpSettings {
        transport: crate::runtime_tunables::effective_mcp::McpTransportSelection::from_servers(&[]),
        oauth: crate::runtime_tunables::effective_mcp::McpOAuthLifecyclePolicy::disabled_fixture(),
        reconnect: iteron_mcp::reconnect::ReconnectPolicy::default(),
        deadlines: iteron_mcp::McpDeadlinePolicy::default(),
        result: iteron_mcp::McpResultPolicy::default(),
    };
    let exposure = McpCapabilityExposure {
        resource_discovery: crate::runtime_tunables::effective_mcp::McpDiscoveryMode::Disabled,
        prompt_discovery: crate::runtime_tunables::effective_mcp::McpDiscoveryMode::Disabled,
        resource_tool_ids: BTreeSet::new(),
        prompt_tool_ids: BTreeSet::new(),
        plugin_binding_ids: BTreeSet::new(),
        server_binding_ids: BTreeSet::new(),
        max_visible_bytes: 0,
    };

    runtime
        .validate_configuration(&policy, &exposure)
        .expect("empty checkpoint must match the empty runtime owner");
    assert_eq!(
        runtime.configured_policy(),
        None,
        "preflight is non-mutating"
    );
    runtime.configure(policy, exposure).unwrap();
    assert_eq!(runtime.configured_policy(), Some(policy));

    let different = EffectiveMcpSettings {
        result: iteron_mcp::McpResultPolicy::new(64, 4096, iteron_mcp::McpSpillCleanup::SessionEnd)
            .unwrap(),
        ..policy
    };
    assert!(
        runtime
            .validate_configuration(
                &different,
                &McpCapabilityExposure {
                    resource_discovery:
                        crate::runtime_tunables::effective_mcp::McpDiscoveryMode::Disabled,
                    prompt_discovery:
                        crate::runtime_tunables::effective_mcp::McpDiscoveryMode::Disabled,
                    resource_tool_ids: BTreeSet::new(),
                    prompt_tool_ids: BTreeSet::new(),
                    plugin_binding_ids: BTreeSet::new(),
                    server_binding_ids: BTreeSet::new(),
                    max_visible_bytes: 0,
                }
            )
            .is_err()
    );
    assert_eq!(runtime.configured_policy(), Some(policy));
}

#[tokio::test]
async fn registration_configuration_and_stale_call_do_not_spawn_then_search_does() {
    let marker = marker();
    let _ = std::fs::remove_file(&marker);
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime = McpRuntimeControl::register(&mut registry, &[fixture(&marker)], &[]).unwrap();

    assert!(
        !marker.exists(),
        "registration must not start configured code"
    );
    assert_eq!(runtime.health()[0].phase, "deferred");
    let denied = registry
        .run_effect(ToolUse {
            id: "unconfigured-resource".into(),
            name: "alpha__resources_list".into(),
            input: json!({}),
        })
        .await
        .into_result();
    assert!(denied.is_error);
    assert!(
        !marker.exists(),
        "an unpinned extension capability must fail before server startup"
    );
    runtime
        .configure(
            settings(iteron_mcp::McpSpillCleanup::SessionEnd),
            exposure("alpha"),
        )
        .unwrap();
    assert!(
        !marker.exists(),
        "checkpoint pinning must remain side-effect free"
    );

    let stale = registry
        .run_effect(ToolUse {
            id: "stale".into(),
            name: "alpha__tool_call".into(),
            input: json!({"name":"echo","arguments":{}}),
        })
        .await
        .into_result();
    assert!(stale.is_error);
    assert!(
        !marker.exists(),
        "an unsearched identity must fail before startup"
    );

    let search = registry
        .run_effect(ToolUse {
            id: "search".into(),
            name: "alpha__tool_search".into(),
            input: json!({"query":"echo","limit":4}),
        })
        .await
        .into_result();
    assert!(!search.is_error, "{}", search.content);
    assert!(search.content.contains("alpha__echo"));
    assert!(
        marker.exists(),
        "the first valid discovery request starts the server"
    );

    let call = registry
        .run_effect(ToolUse {
            id: "call".into(),
            name: "alpha__tool_call".into(),
            input: json!({"name":"alpha__echo","arguments":{}}),
        })
        .await
        .into_result();
    assert!(!call.is_error, "{}", call.content);
    assert!(call.content.contains("pong"));
    let health = &runtime.health()[0];
    assert_eq!(health.phase, "ready");
    assert_eq!(health.generation, Some(1));
    assert!(health.catalog_current);
    assert_eq!(
        health.negotiated_protocol_version.as_deref(),
        Some("2024-11-05")
    );

    runtime.stop("alpha").await.unwrap();
    assert_eq!(runtime.health()[0].phase, "stopped");
    runtime.restart("alpha").await.unwrap();
    assert_eq!(runtime.health()[0].phase, "deferred");
    let _ = std::fs::remove_file(marker);
}

#[tokio::test]
async fn session_runtime_uses_2026_discovery_without_stateful_initialize() {
    let marker = marker();
    let _ = std::fs::remove_file(&marker);
    let config = modern_fixture(&marker);
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime =
        McpRuntimeControl::register(&mut registry, std::slice::from_ref(&config), &[]).unwrap();
    runtime
        .configure(
            settings(iteron_mcp::McpSpillCleanup::SessionEnd),
            bound_exposure(&config),
        )
        .unwrap();
    let search = registry
        .run_effect(ToolUse {
            id: "search-modern".into(),
            name: "alpha__tool_search".into(),
            input: json!({"query":"echo","limit":4}),
        })
        .await
        .into_result();
    assert!(!search.is_error, "{}", search.content);
    let call = registry
        .run_effect(ToolUse {
            id: "call-modern".into(),
            name: "alpha__tool_call".into(),
            input: json!({"name":"alpha__echo","arguments":{}}),
        })
        .await
        .into_result();
    assert!(!call.is_error, "{}", call.content);
    assert_eq!(
        runtime.health()[0].negotiated_protocol_version.as_deref(),
        Some("2026-07-28")
    );
    runtime.stop("alpha").await.unwrap();
    let _ = std::fs::remove_file(marker);
}

#[tokio::test]
async fn session_runtime_completes_2026_mrtr_and_echoes_state_on_the_same_server() {
    let resumed_request = marker();
    let marker = marker();
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::remove_file(&resumed_request);
    let config = modern_mrtr_fixture(&marker, &resumed_request);
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime =
        McpRuntimeControl::register(&mut registry, std::slice::from_ref(&config), &[]).unwrap();
    runtime
        .configure(
            settings(iteron_mcp::McpSpillCleanup::SessionEnd),
            bound_exposure(&config),
        )
        .unwrap();
    let states = Arc::new(StdMutex::new(Vec::new()));
    runtime
        .install_mrtr_handler(Arc::new(RecordingMrtrHandler {
            states: states.clone(),
        }))
        .unwrap();
    let search = registry
        .run_effect(ToolUse {
            id: "search-mrtr".into(),
            name: "alpha__tool_search".into(),
            input: json!({"query":"profile"}),
        })
        .await
        .into_result();
    assert!(!search.is_error, "{}", search.content);
    let call = registry
        .run_effect(ToolUse {
            id: "call-mrtr".into(),
            name: "alpha__tool_call".into(),
            input: json!({"name":"alpha__profile","arguments":{}}),
        })
        .await
        .into_result();
    assert!(!call.is_error, "{}", call.content);
    assert!(call.content.contains("profile accepted"));
    assert_eq!(*states.lock().unwrap(), vec![Some("round-1".into())]);
    let resumed = std::fs::read_to_string(&resumed_request).unwrap();
    assert!(resumed.contains(r#""requestState":"round-1""#));
    assert!(resumed.contains(r#""inputResponses""#));
    assert!(resumed.contains(r#""action":"accept""#));
    assert!(resumed.contains(r#""name":"Alice""#));
    runtime.stop("alpha").await.unwrap();
    let _ = std::fs::remove_file(marker);
    let _ = std::fs::remove_file(resumed_request);
}

#[tokio::test]
async fn a_2025_session_never_invokes_the_mrtr_handler() {
    let marker = marker();
    let _ = std::fs::remove_file(&marker);
    let config = stateful_2025_fixture(&marker);
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime =
        McpRuntimeControl::register(&mut registry, std::slice::from_ref(&config), &[]).unwrap();
    runtime
        .configure(
            settings(iteron_mcp::McpSpillCleanup::SessionEnd),
            bound_exposure(&config),
        )
        .unwrap();
    let states = Arc::new(StdMutex::new(Vec::new()));
    runtime
        .install_mrtr_handler(Arc::new(RecordingMrtrHandler {
            states: states.clone(),
        }))
        .unwrap();
    let search = registry
        .run_effect(ToolUse {
            id: "search-2025".into(),
            name: "alpha__tool_search".into(),
            input: json!({"query":"echo"}),
        })
        .await
        .into_result();
    assert!(!search.is_error, "{}", search.content);
    let call = registry
        .run_effect(ToolUse {
            id: "call-2025".into(),
            name: "alpha__tool_call".into(),
            input: json!({"name":"alpha__echo","arguments":{}}),
        })
        .await
        .into_result();
    assert!(!call.is_error, "{}", call.content);
    assert!(states.lock().unwrap().is_empty());
    assert_eq!(
        runtime.health()[0].negotiated_protocol_version.as_deref(),
        Some("2025-11-25")
    );
    runtime.stop("alpha").await.unwrap();
    let _ = std::fs::remove_file(marker);
}

#[test]
fn capability_exposure_must_exactly_match_registered_proxies() {
    let marker = marker();
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime = McpRuntimeControl::register(&mut registry, &[fixture(&marker)], &[]).unwrap();
    let mut stale = exposure("alpha");
    stale.resource_tool_ids.remove("alpha__resources_read");
    assert!(
        runtime
            .configure(settings(iteron_mcp::McpSpillCleanup::SessionEnd), stale,)
            .is_err(),
        "a narrowed or stale checkpoint cannot silently change the registered surface"
    );
    assert!(!marker.exists());
}

#[test]
fn resumed_transport_drift_is_refused_before_http_dispatch() {
    let old = fixture(&marker());
    let live = http_fixture(None);
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime =
        McpRuntimeControl::register(&mut registry, std::slice::from_ref(&live), &[]).unwrap();
    let checkpoint = settings(iteron_mcp::McpSpillCleanup::SessionEnd)
        .with_live_bindings_for_test(&[old])
        .unwrap();
    assert!(
        runtime
            .configure(checkpoint, bound_exposure(&live))
            .is_err(),
        "a resumed stdio checkpoint cannot be reinterpreted as HTTP"
    );
    let health = runtime.health();
    assert_eq!(health[0].phase, "deferred");
    assert_eq!(
        health[0].generation, None,
        "configure must dispatch nothing"
    );
}

#[test]
fn resumed_oauth_lifecycle_drift_is_refused_before_http_dispatch() {
    let old = http_fixture(Some(bearer_oauth()));
    let live = http_fixture(Some(refresh_oauth()));
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime =
        McpRuntimeControl::register(&mut registry, std::slice::from_ref(&live), &[]).unwrap();
    let checkpoint = settings(iteron_mcp::McpSpillCleanup::SessionEnd)
        .with_live_bindings_for_test(&[old])
        .unwrap();
    assert!(
        runtime
            .configure(checkpoint, bound_exposure(&live))
            .is_err(),
        "a resumed bearer-only checkpoint cannot gain refresh/revocation lifecycle"
    );
    let health = runtime.health();
    assert_eq!(health[0].phase, "deferred");
    assert_eq!(
        health[0].generation, None,
        "configure must dispatch nothing"
    );
}

#[tokio::test]
async fn plugin_server_dispatch_requires_the_exact_checkpoint_identity() {
    let marker = marker();
    let _ = std::fs::remove_file(&marker);
    let mut plugin = fixture(&marker);
    plugin.origin = crate::config::McpServerOrigin::plugin_fixture("docs-pack", "1.2.3");
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime = McpRuntimeControl::register(&mut registry, &[plugin.clone()], &[]).unwrap();

    assert!(
        runtime
            .configure(
                settings(iteron_mcp::McpSpillCleanup::SessionEnd),
                exposure("alpha"),
            )
            .is_err(),
        "a value-v1 checkpoint's empty plugin set must not admit a live plugin server"
    );
    assert!(!marker.exists());

    assert!(
        runtime
            .configure(
                settings(iteron_mcp::McpSpillCleanup::SessionEnd),
                plugin_exposure(&plugin, "docs-pack", "1.2.2"),
            )
            .is_err(),
        "a stale plugin version must not satisfy the live server binding"
    );
    assert!(!marker.exists());

    runtime
        .configure(
            settings(iteron_mcp::McpSpillCleanup::SessionEnd),
            plugin_exposure(&plugin, "docs-pack", "1.2.3"),
        )
        .unwrap();
    let result = registry
        .run_effect(ToolUse {
            id: "plugin-search".into(),
            name: "alpha__tool_search".into(),
            input: json!({"query":"echo"}),
        })
        .await
        .into_result();
    assert!(!result.is_error, "{}", result.content);
    assert!(
        marker.exists(),
        "the exact plugin identity may start its server"
    );
    let health = runtime.health();
    assert_eq!(health[0].origin, "plugin");
    let expected_identity = crate::config::McpServerOrigin::plugin_fixture("docs-pack", "1.2.3")
        .plugin_binding_id("alpha")
        .unwrap()
        .unwrap();
    assert_eq!(
        health[0].plugin_identity.as_deref(),
        Some(expected_identity.as_str())
    );
    runtime.stop("alpha").await.unwrap();
    let _ = std::fs::remove_file(marker);
}

#[test]
fn plugin_binding_identity_accepts_full_semver_and_indexes_the_exact_server() {
    let origin =
        crate::config::McpServerOrigin::plugin_fixture("docs-pack", "1.2.3-rc.1+darwin.arm64");
    let alpha = origin.plugin_binding_id("alpha").unwrap().unwrap();
    let beta = origin.plugin_binding_id("beta").unwrap().unwrap();
    assert_ne!(alpha, beta);
    assert!(alpha.owns_server("alpha"));
    assert!(!alpha.owns_server("beta"));
    assert_eq!(
        crate::config::PluginMcpBindingId::parse(alpha.as_str()).unwrap(),
        alpha
    );
}

#[tokio::test]
async fn pinned_capability_exposure_allows_the_live_resource_proxy() {
    let marker = marker();
    let _ = std::fs::remove_file(&marker);
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime = McpRuntimeControl::register(&mut registry, &[fixture(&marker)], &[]).unwrap();
    runtime
        .configure(
            settings(iteron_mcp::McpSpillCleanup::SessionEnd),
            exposure("alpha"),
        )
        .unwrap();
    let result = registry
        .run_effect(ToolUse {
            id: "resource".into(),
            name: "alpha__resources_list".into(),
            input: json!({}),
        })
        .await
        .into_result();
    assert!(!result.is_error, "{}", result.content);
    assert!(
        marker.exists(),
        "the admitted lazy proxy starts its exact server"
    );
    runtime.stop("alpha").await.unwrap();
    let _ = std::fs::remove_file(marker);
}

#[test]
fn all_declared_cleanup_scopes_are_accepted_by_the_runtime_owner() {
    for cleanup in [
        iteron_mcp::McpSpillCleanup::ToolEnd,
        iteron_mcp::McpSpillCleanup::TurnEnd,
        iteron_mcp::McpSpillCleanup::RunEnd,
        iteron_mcp::McpSpillCleanup::SessionEnd,
    ] {
        assert_eq!(settings(cleanup).result.cleanup(), cleanup);
    }
}
