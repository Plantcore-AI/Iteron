//! Trusted-user MCP composition and registry wiring.

mod session;

pub(crate) use session::{McpRuntimeControl, McpServerHealth};

use crate::config::{McpServerConfig, McpTransportConfig};
use iteron_protocol::ToolSpec;
use iteron_tools::Registry;
#[cfg(test)]
use std::collections::BTreeSet;
use std::sync::Arc;

/// Latency reported for a definite MCP failure that carried no dispatch evidence. Zero, because
/// no interval was actually observed and inventing one would corrupt latency accounting.
const UNMEASURED_DISPATCH_LATENCY_MS: u64 = 0;

#[cfg(test)]
struct DiscoveredServer {
    client: Arc<ConfiguredMcpClient>,
    name: String,
    specs: Vec<ToolSpec>,
    extensions: Vec<(ToolSpec, &'static str)>,
}

pub(crate) enum ConfiguredMcpClient {
    Stdio(Arc<iteron_mcp::McpClient>),
    Http(Arc<iteron_mcp::McpRemoteClient>),
}

impl ConfiguredMcpClient {
    fn negotiated_protocol_version(&self) -> &str {
        match self {
            Self::Stdio(client) => client.negotiated_protocol_version(),
            Self::Http(client) => client.negotiated_protocol_version(),
        }
    }
    #[cfg(test)]
    fn capabilities(&self) -> iteron_mcp::McpServerCapabilities {
        match self {
            Self::Stdio(client) => client.capabilities(),
            Self::Http(client) => client.capabilities(),
        }
    }

    #[cfg(test)]
    async fn call_extension(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<String, iteron_mcp::McpError> {
        match self {
            Self::Stdio(client) => client.call_extension_rendered(method, params).await,
            Self::Http(client) => client.call_extension_rendered(method, params).await,
        }
    }

    async fn list_tools_governed(
        &self,
        filter: &iteron_mcp::McpToolFilter,
        policy: &iteron_mcp::McpServerPolicy,
        ceiling: iteron_protocol::capability_set::CapabilitySet,
    ) -> Result<Vec<ToolSpec>, iteron_mcp::McpError> {
        match self {
            Self::Stdio(client) => client.list_tools_governed(filter, policy, ceiling).await,
            Self::Http(client) => client.list_tools_governed(filter, policy, ceiling).await,
        }
    }

    async fn call_tool_outcome_observed<F>(
        &self,
        name: &str,
        arguments: serde_json::Value,
        on_dispatch: F,
    ) -> iteron_mcp::McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        match self {
            Self::Stdio(client) => {
                client
                    .call_tool_outcome_observed(name, arguments, on_dispatch)
                    .await
            }
            Self::Http(client) => {
                client
                    .call_tool_outcome_observed(name, arguments, on_dispatch)
                    .await
            }
        }
    }

    async fn call_extension_outcome_observed<F>(
        &self,
        method: &str,
        params: serde_json::Value,
        on_dispatch: F,
    ) -> iteron_mcp::McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        match self {
            Self::Stdio(client) => {
                client
                    .call_extension_outcome_observed(method, params, on_dispatch)
                    .await
            }
            Self::Http(client) => {
                client
                    .call_extension_outcome_observed(method, params, on_dispatch)
                    .await
            }
        }
    }

    fn cleanup_spills(
        &self,
        boundary: iteron_mcp::McpSpillCleanup,
    ) -> Result<(), iteron_mcp::McpError> {
        match self {
            Self::Stdio(client) => client.cleanup_spills(boundary),
            Self::Http(client) => client.cleanup_spills(boundary),
        }
    }
}

/// Register session-owned lazy MCP proxies without starting a configured process.
///
/// The returned control must be pinned to the decoded run checkpoint before the registry becomes
/// reachable by the agent. Stdio and HTTP discovery then happen only through a proxy invocation;
/// both transports share exact searched-contract identity and unknown-effect refusal semantics.
pub(crate) fn register_configured_servers(
    registry: &mut Registry,
    servers: &[McpServerConfig],
    sensitive_env_names: &[String],
) -> anyhow::Result<McpRuntimeControl> {
    McpRuntimeControl::register(registry, servers, sensitive_env_names)
}

#[cfg(test)]
async fn register_configured_servers_with_limit(
    registry: &mut Registry,
    servers: &[McpServerConfig],
    sensitive_env_names: &[String],
    combined_limit: usize,
) -> anyhow::Result<()> {
    let mut combined = iteron_mcp::CombinedToolCatalog::with_limit(combined_limit)?;
    let mut discovered = Vec::with_capacity(servers.len());

    for server in servers {
        match discover_configured_server(server, sensitive_env_names).await {
            Ok(server) => {
                combined.admit(&server.specs)?;
                let extension_only = server
                    .extensions
                    .iter()
                    .map(|(spec, _)| spec.clone())
                    .collect::<Vec<_>>();
                combined.admit(&extension_only)?;
                discovered.push(server);
            }
            Err(error) => {
                let diagnostic = startup_error_line(&server.name, "connect", &error);
                eprintln!("{diagnostic}");
            }
        }
    }

    // MCP names are unique among themselves by `CombinedToolCatalog`; check native/custom tools
    // too before the first mutation so a future built-in containing `__` cannot create a partial
    // registration batch.
    let existing: BTreeSet<String> = registry.specs().into_iter().map(|spec| spec.name).collect();
    if discovered
        .iter()
        .flat_map(|server| &server.specs)
        .chain(
            discovered
                .iter()
                .flat_map(|server| server.extensions.iter().map(|(spec, _)| spec)),
        )
        .any(|spec| existing.contains(&spec.name))
    {
        return Err(iteron_mcp::McpError::ToolNameCollision.into());
    }

    for server in discovered {
        let exposed = server.specs.len() + server.extensions.len();
        for spec in server.specs {
            register_mcp_tool(registry, server.client.clone(), &server.name, spec).map_err(
                |_| anyhow::anyhow!("MCP tool registration failed after bounded preflight"),
            )?;
        }
        for (spec, method) in server.extensions {
            register_mcp_extension(registry, server.client.clone(), spec, method).map_err(
                |_| anyhow::anyhow!("MCP extension registration failed after bounded preflight"),
            )?;
        }
        eprintln!("mcp: connected `{}` ({exposed} exposed tools)", server.name);
    }
    Ok(())
}

/// Connect and perform read-only discovery under the same finite reconnect schedule used by the
/// managed MCP lifecycle. No effecting tool call is replayed here: registration has not exposed a
/// callable tool yet, and every failed client is dropped before the next generation starts.
#[cfg(test)]
async fn discover_configured_server(
    server: &McpServerConfig,
    sensitive_env_names: &[String],
) -> Result<DiscoveredServer, iteron_mcp::McpError> {
    let reconnect = iteron_mcp::reconnect::ReconnectPolicy::default();
    let mut attempt = 0;
    loop {
        let result = async {
            let client = Arc::new(connect_configured_server(server, sensitive_env_names).await?);
            let specs = client
                .list_tools_governed(&server.tools, &server.policy, host_ceiling())
                .await?;
            let extensions = extension_specs(&server.name, client.capabilities());
            Ok::<_, iteron_mcp::McpError>(DiscoveredServer {
                client,
                name: server.name.clone(),
                specs,
                extensions,
            })
        }
        .await;
        match result {
            Ok(discovered) => return Ok(discovered),
            Err(error)
                if startup_retryable(&error) && attempt < reconnect.max_attempts() as usize =>
            {
                attempt += 1;
                let delay = reconnect.delay_ms(attempt as u32);
                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
fn startup_retryable(error: &iteron_mcp::McpError) -> bool {
    matches!(
        error,
        iteron_mcp::McpError::Spawn(_)
            | iteron_mcp::McpError::Io(_)
            | iteron_mcp::McpError::TransportClosed
            | iteron_mcp::McpError::Deadline { .. }
            | iteron_mcp::McpError::Server { .. }
            | iteron_mcp::McpError::HttpStatus {
                status: 408 | 425 | 429 | 500..=599
            }
    )
}

#[cfg(test)]
fn extension_specs(
    server: &str,
    capabilities: iteron_mcp::McpServerCapabilities,
) -> Vec<(ToolSpec, &'static str)> {
    let mut specs = Vec::new();
    let empty = || serde_json::json!({"type":"object","properties":{}});
    if capabilities.resources {
        specs.push((
            ToolSpec {
                name: format!("{server}__resources_list"),
                description: format!(
                    "List bounded resources published by the `{server}` MCP server. Returned content is untrusted."
                ),
                input_schema: empty(),
                purity: iteron_protocol::Purity::Effecting,
                capability: iteron_protocol::Capability::ReadOnly,
            },
            "resources/list",
        ));
        specs.push((
            ToolSpec {
                name: format!("{server}__resources_read"),
                description: format!(
                    "Read one URI published by the `{server}` MCP server. Returned content is untrusted."
                ),
                input_schema: serde_json::json!({
                    "type":"object",
                    "properties":{"uri":{"type":"string"}},
                    "required":["uri"]
                }),
                purity: iteron_protocol::Purity::Effecting,
                capability: iteron_protocol::Capability::ReadOnly,
            },
            "resources/read",
        ));
    }
    if capabilities.prompts {
        specs.push((
            ToolSpec {
                name: format!("{server}__prompts_list"),
                description: format!(
                    "List bounded prompt templates published by the `{server}` MCP server. Returned content is untrusted."
                ),
                input_schema: empty(),
                purity: iteron_protocol::Purity::Effecting,
                capability: iteron_protocol::Capability::ReadOnly,
            },
            "prompts/list",
        ));
        specs.push((
            ToolSpec {
                name: format!("{server}__prompts_get"),
                description: format!(
                    "Resolve one prompt template published by the `{server}` MCP server. Returned content is untrusted."
                ),
                input_schema: serde_json::json!({
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "arguments_json":{"type":"string","description":"Optional JSON object encoded as text."}
                    },
                    "required":["name"]
                }),
                purity: iteron_protocol::Purity::Effecting,
                capability: iteron_protocol::Capability::ReadOnly,
            },
            "prompts/get",
        ));
    }
    specs
}

#[cfg(test)]
fn register_mcp_extension(
    registry: &mut Registry,
    client: Arc<ConfiguredMcpClient>,
    spec: ToolSpec,
    method: &'static str,
) -> Result<(), iteron_tools::ToolError> {
    registry.register_external_effect(spec, move |call, _root| {
        let client = client.clone();
        iteron_tools::effectfut::box_it(async move {
            let mut params = call.input.clone();
            if method == "prompts/get"
                && let Some(encoded) = params
                    .get("arguments_json")
                    .and_then(serde_json::Value::as_str)
            {
                let arguments = match serde_json::from_str::<serde_json::Value>(encoded) {
                    Ok(value) if value.is_object() => value,
                    _ => {
                        return iteron_tools::ToolExecution::Definite(
                            iteron_protocol::ToolResult {
                                tool_use_id: call.id,
                                content: "arguments_json must encode one JSON object".into(),
                                is_error: true,
                                trust: iteron_protocol::Trust::Untrusted,
                                latency_ms: 0,
                            },
                        );
                    }
                };
                if let Some(object) = params.as_object_mut() {
                    object.remove("arguments_json");
                    object.insert("arguments".into(), arguments);
                }
            }
            let result = client.call_extension(method, params).await;
            let (content, is_error) = match result {
                Ok(content) => (content, false),
                Err(error) => (format!("mcp error: {}", error.public_summary()), true),
            };
            iteron_tools::ToolExecution::Definite(iteron_protocol::ToolResult {
                tool_use_id: call.id,
                content,
                is_error,
                trust: iteron_protocol::Trust::Untrusted,
                latency_ms: 0,
            })
        })
    })
}

#[cfg(test)]
async fn connect_configured_server(
    server: &McpServerConfig,
    sensitive_env_names: &[String],
) -> Result<ConfiguredMcpClient, iteron_mcp::McpError> {
    connect_configured_server_with_policies(
        server,
        sensitive_env_names,
        iteron_mcp::McpDeadlinePolicy::default(),
        iteron_mcp::McpResultPolicy::default(),
    )
    .await
}

async fn connect_configured_server_with_policies(
    server: &McpServerConfig,
    sensitive_env_names: &[String],
    deadlines: iteron_mcp::McpDeadlinePolicy,
    result_policy: iteron_mcp::McpResultPolicy,
) -> Result<ConfiguredMcpClient, iteron_mcp::McpError> {
    match server.transport {
        McpTransportConfig::Stdio => {
            let command =
                server
                    .command
                    .as_deref()
                    .ok_or(iteron_mcp::McpError::InvalidEndpoint {
                        field: "command",
                        limit: 4096,
                    })?;
            iteron_mcp::McpClient::connect_with_sensitive_env_names(
                command,
                &server.args,
                &server.name,
                sensitive_env_names,
            )
            .await
            .map(|client| ConfiguredMcpClient::Stdio(Arc::new(client)))
        }
        McpTransportConfig::Http => {
            let endpoint = iteron_mcp::http::McpHttpEndpoint::parse(server.url.as_deref().ok_or(
                iteron_mcp::McpError::InvalidEndpoint {
                    field: "url",
                    limit: iteron_mcp::http::MAX_MCP_HTTP_URL_BYTES,
                },
            )?)?;
            let policy = iteron_mcp::http::McpHttpHeaderPolicy::new(
                server.header_env.keys().cloned().collect(),
            )?;
            let mut headers = Vec::with_capacity(server.header_env.len());
            for (name, env_name) in &server.header_env {
                let value =
                    std::env::var(env_name).map_err(|_| iteron_mcp::McpError::InvalidEndpoint {
                        field: "header_env_value",
                        limit: 8192,
                    })?;
                headers.push((name.clone(), iteron_mcp::http::McpHeaderValue::new(value)?));
            }
            let credential = server
                .oauth
                .as_ref()
                .map(|oauth| {
                    let secret = std::env::var(&oauth.access_token_env).map_err(|_| {
                        iteron_mcp::McpError::Credential(iteron_mcp::token::TokenError::Absent)
                    })?;
                    let expires_at = oauth
                        .expires_at_env
                        .as_ref()
                        .map(|name| {
                            std::env::var(name)
                                .ok()
                                .and_then(|value| value.parse::<u64>().ok())
                                .ok_or(iteron_mcp::McpError::Credential(
                                    iteron_mcp::token::TokenError::Expired { skew: 30 },
                                ))
                        })
                        .transpose()?
                        .unwrap_or(u64::MAX);
                    Ok::<_, iteron_mcp::McpError>(iteron_mcp::token::Token::new(secret, expires_at))
                })
                .transpose()?;
            let oauth_grant = server
                .oauth
                .as_ref()
                .and_then(|oauth| {
                    oauth
                        .refresh_url
                        .as_ref()
                        .zip(oauth.refresh_token_env.as_ref())
                        .map(|(refresh_url, refresh_token_env)| {
                            let refresh_token = std::env::var(refresh_token_env).map_err(|_| {
                                iteron_mcp::McpError::Credential(
                                    iteron_mcp::token::TokenError::Absent,
                                )
                            })?;
                            let client_secret = oauth
                                .client_secret_env
                                .as_ref()
                                .map(|name| {
                                    std::env::var(name).map_err(|_| {
                                        iteron_mcp::McpError::Credential(
                                            iteron_mcp::token::TokenError::Absent,
                                        )
                                    })
                                })
                                .transpose()?;
                            iteron_mcp::oauth::OAuthRefreshGrant::new(
                                iteron_mcp::http::McpHttpEndpoint::parse(refresh_url)?,
                                oauth
                                    .revoke_url
                                    .as_deref()
                                    .map(iteron_mcp::http::McpHttpEndpoint::parse)
                                    .transpose()?,
                                refresh_token,
                                oauth.client_id.clone(),
                                client_secret,
                            )
                        })
                })
                .transpose()?;
            iteron_mcp::McpRemoteClient::connect_with_policies(
                endpoint,
                server.name.clone(),
                credential,
                policy,
                headers,
                oauth_grant,
                deadlines.http(),
                result_policy,
            )
            .await
            .map(|client| ConfiguredMcpClient::Http(Arc::new(client)))
        }
    }
}

/// The authority this composition root is willing to admit for any MCP server, before that
/// server's own policy narrows it further.
///
/// It is named here, in the trusted host, rather than read from configuration, because it is the
/// input a per-server policy may only ever intersect. An installed server participates in the
/// narrowing and never in this value, which is what makes "an installed server cannot widen what
/// the host allows" a property of the composition rather than a rule someone has to remember.
fn host_ceiling() -> iteron_protocol::capability_set::CapabilitySet {
    iteron_mcp::default_host_ceiling()
}

#[cfg(test)]
fn startup_error_line(server_name: &str, operation: &str, error: &iteron_mcp::McpError) -> String {
    format!(
        "mcp {server_name}: {operation} failed: {}",
        error.public_summary()
    )
}

#[cfg(test)]
pub(crate) fn register_mcp_tool(
    registry: &mut Registry,
    client: Arc<ConfiguredMcpClient>,
    server_name: &str,
    spec: ToolSpec,
) -> Result<(), iteron_tools::ToolError> {
    let prefix = format!("{server_name}__");
    let bare = spec.name.strip_prefix(&prefix).ok_or_else(|| {
        iteron_tools::ToolError::Registration(
            "MCP tool does not match its validated server namespace".into(),
        )
    })?;
    let attribution = iteron_tools::McpEffectAttribution::new(server_name, bare.to_string());
    let bare = bare.to_string();
    registry.register_mcp_effect(spec, attribution, move |call, _root, dispatch_clock| {
        let client = client.clone();
        let bare = bare.clone();
        iteron_tools::effectfut::box_it(async move {
            let clock = dispatch_clock.clone();
            let outcome = client
                .call_tool_outcome_observed(&bare, call.input.clone(), move || {
                    clock.mark_dispatched()
                })
                .await;
            mcp_tool_execution(call.id, outcome)
        })
    })
}

fn mcp_tool_execution(
    tool_use_id: String,
    outcome: iteron_mcp::McpToolOutcome,
) -> iteron_tools::ToolExecution {
    match outcome {
        iteron_mcp::McpToolOutcome::Completed {
            content,
            is_error,
            evidence,
        } => iteron_tools::ToolExecution::Definite(iteron_protocol::ToolResult {
            tool_use_id,
            content,
            is_error,
            trust: iteron_protocol::Trust::Untrusted,
            latency_ms: evidence.dispatch_to_terminal_ms.get(),
        }),
        iteron_mcp::McpToolOutcome::FailedDefinite { error, evidence } => {
            iteron_tools::ToolExecution::Definite(iteron_protocol::ToolResult {
                tool_use_id,
                content: format!("mcp error: {}", error.public_summary()),
                is_error: true,
                trust: iteron_protocol::Trust::Untrusted,
                latency_ms: evidence
                    .map(|evidence| evidence.dispatch_to_terminal_ms.get())
                    .unwrap_or(iteron_tunables::param_integer("cli.mcp.unmeasured_dispatch_latency_ms", UNMEASURED_DISPATCH_LATENCY_MS)),
            })
        }
        iteron_mcp::McpToolOutcome::Unknown { evidence, .. } => {
            iteron_tools::ToolExecution::Unknown(iteron_protocol::ToolResult {
                tool_use_id,
                content: "MCP request was dispatched but no authoritative terminal response was observed; remote outcome is unknown and Core will not retry it automatically".into(),
                is_error: true,
                trust: iteron_protocol::Trust::Untrusted,
                latency_ms: evidence.dispatch_to_terminal_ms.get(),
            })
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::{FILE_CONFIG_SCHEMA_VERSION, FileConfig};
    use serde_json::json;

    const HANDSHAKE: &str = concat!(
        "IFS= read -r initialize; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
        "IFS= read -r initialized; ",
        "IFS= read -r list; "
    );

    fn server(
        name: &str,
        tools: serde_json::Value,
        filter: serde_json::Value,
    ) -> serde_json::Value {
        governed_server(name, tools, filter, json!({}))
    }

    fn governed_server(
        name: &str,
        tools: serde_json::Value,
        filter: serde_json::Value,
        policy: serde_json::Value,
    ) -> serde_json::Value {
        let response = json!({"jsonrpc":"2.0","id":2,"result":{"tools":tools}}).to_string();
        let script = format!("{HANDSHAKE}printf '%s\\n' \"$1\"; exec sleep 60");
        json!({
            "name": name,
            "command": "/bin/bash",
            "args": ["-c", script, "mcp-fixture", response],
            "tools": filter,
            "policy": policy
        })
    }

    #[tokio::test]
    async fn trusted_filters_exclude_tools_and_same_bare_names_register_twice() {
        let document = json!({
            "schema_version": FILE_CONFIG_SCHEMA_VERSION,
            "mcp_servers": [
                server(
                    "alpha",
                    json!([
                        {"name":"shared"},
                        {"name":"visible"},
                        {"name":"blocked", "description":"must never register"}
                    ]),
                    json!({"allow":["shared", "visible", "blocked"], "deny":["blocked"]})
                ),
                server(
                    "beta",
                    json!([
                        {"name":"shared"},
                        {"name":"hidden", "description":"must never register"}
                    ]),
                    json!({"deny":["hidden"]})
                )
            ]
        });
        let trusted_user = FileConfig::parse(&document.to_string()).unwrap();
        let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
        register_configured_servers_with_limit(
            &mut registry,
            trusted_user.mcp_servers.as_deref().unwrap(),
            &[],
            4,
        )
        .await
        .unwrap();

        let names: BTreeSet<_> = registry.specs().into_iter().map(|spec| spec.name).collect();
        assert!(names.contains("alpha__shared"));
        assert!(names.contains("beta__shared"));
        assert!(names.contains("alpha__visible"));
        assert!(!names.contains("alpha__blocked"));
        assert!(!names.contains("beta__hidden"));
    }

    #[tokio::test]
    async fn declared_resources_and_prompts_are_real_namespaced_model_tools() {
        let script = concat!(
            "IFS= read -r initialize; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{\"tools\":{},\"resources\":{},\"prompts\":{}}}}'; ",
            "IFS= read -r initialized; ",
            "IFS= read -r list; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}'; ",
            "IFS= read -r resource; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":[{\"uri\":\"plantcore://guide\",\"name\":\"Guide\"}]}}'; ",
            "exec sleep 60"
        );
        let document = json!({
            "schema_version": FILE_CONFIG_SCHEMA_VERSION,
            "mcp_servers": [{
                "name":"docs",
                "command":"/bin/bash",
                "args":["-c", script]
            }]
        });
        let trusted = FileConfig::parse(&document.to_string()).unwrap();
        let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
        register_configured_servers_with_limit(
            &mut registry,
            trusted.mcp_servers.as_deref().unwrap(),
            &[],
            iteron_mcp::MAX_COMBINED_MCP_TOOLS,
        )
        .await
        .unwrap();
        let names: Vec<_> = registry.specs().into_iter().map(|spec| spec.name).collect();
        for expected in [
            "docs__resources_list",
            "docs__resources_read",
            "docs__prompts_list",
            "docs__prompts_get",
        ] {
            assert!(names.iter().any(|name| name == expected), "{names:?}");
        }
        let result = registry
            .run_effect(iteron_protocol::ToolUse {
                id: "resource-list".into(),
                name: "docs__resources_list".into(),
                input: json!({}),
            })
            .await
            .into_result();
        assert!(!result.is_error, "{}", result.content);
        assert!(result.content.contains("plantcore://guide"));
        assert_eq!(result.trust, iteron_protocol::Trust::Untrusted);
    }

    #[tokio::test]
    async fn a_server_policy_bounds_tools_the_operator_never_named_and_cannot_widen_the_host() {
        // The distinction this test exists to protect: a deny list binds names, a policy binds the
        // server. `alpha` publishes a tool the operator's filter never mentions -- an empty
        // allow-list admits it, because a name that did not exist at configuration time could not
        // have been listed. `policy.capabilities: []` is the statement that covers it anyway.
        //
        // `beta` is the adversarial half: it declares every capability class for itself and asks
        // again, louder, for one tool. The host admits external effect and nothing else, and the
        // declaration must move neither the set of registered tools nor their capability.
        let document = json!({
            "schema_version": FILE_CONFIG_SCHEMA_VERSION,
            "mcp_servers": [
                governed_server(
                    "alpha",
                    json!([
                        {"name":"known"},
                        {"name":"published-after-install", "description":"must never register"}
                    ]),
                    json!({}),
                    json!({"capabilities": []})
                ),
                governed_server(
                    "beta",
                    json!([{"name":"ordinary"}, {"name":"escalate"}]),
                    json!({}),
                    json!({
                        "capabilities": [
                            "read_only", "reversible_local", "code_executing",
                            "trust_mutating", "irreversible_external"
                        ],
                        "tools": {"escalate": ["read_only"]}
                    })
                )
            ]
        });
        let trusted_user = FileConfig::parse(&document.to_string()).unwrap();
        let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
        register_configured_servers_with_limit(
            &mut registry,
            trusted_user.mcp_servers.as_deref().unwrap(),
            &[],
            8,
        )
        .await
        .unwrap();

        let specs = registry.specs();
        let names: BTreeSet<_> = specs.iter().map(|spec| spec.name.clone()).collect();
        assert!(
            !names.contains("alpha__known") && !names.contains("alpha__published-after-install"),
            "a server-wide ceiling covers tools the operator could not have named"
        );
        assert!(
            !names.contains("beta__escalate"),
            "a per-tool ceiling disjoint from the demanded class excludes that tool"
        );
        assert!(names.contains("beta__ordinary"));
        let ordinary = specs
            .iter()
            .find(|spec| spec.name == "beta__ordinary")
            .expect("the admitted tool is registered");
        assert_eq!(
            ordinary.capability,
            iteron_protocol::Capability::IrreversibleExternal,
            "a server declaring every class must not raise the class its tools register with"
        );
    }

    #[tokio::test]
    async fn an_unconfigured_policy_registers_exactly_what_the_filter_alone_would() {
        // Adding the authority gate must not become a silent deny-by-default for the operators who
        // configured no policy at all.
        let tools = json!([{"name":"one"}, {"name":"two"}]);
        let document = json!({
            "schema_version": FILE_CONFIG_SCHEMA_VERSION,
            "mcp_servers": [server("alpha", tools, json!({"deny":["two"]}))]
        });
        let trusted_user = FileConfig::parse(&document.to_string()).unwrap();
        assert!(
            trusted_user.mcp_servers.as_deref().unwrap()[0]
                .policy
                .is_empty(),
            "an absent policy stays absent rather than defaulting to some ceiling"
        );
        let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
        register_configured_servers_with_limit(
            &mut registry,
            trusted_user.mcp_servers.as_deref().unwrap(),
            &[],
            8,
        )
        .await
        .unwrap();

        let names: BTreeSet<_> = registry.specs().into_iter().map(|spec| spec.name).collect();
        assert!(names.contains("alpha__one"));
        assert!(!names.contains("alpha__two"));
    }

    #[tokio::test]
    async fn combined_limit_fails_before_any_mcp_tool_is_registered() {
        let secret_shaped = "opaque-secret-shaped-name";
        let document = json!({
            "schema_version": FILE_CONFIG_SCHEMA_VERSION,
            "mcp_servers": [server(
                "alpha",
                json!([{"name":"one"}, {"name":secret_shaped}]),
                json!({})
            )]
        });
        let trusted_user = FileConfig::parse(&document.to_string()).unwrap();
        let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
        let before = registry.specs().len();
        let error = register_configured_servers_with_limit(
            &mut registry,
            trusted_user.mcp_servers.as_deref().unwrap(),
            &[],
            1,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error.downcast_ref::<iteron_mcp::McpError>(),
            Some(iteron_mcp::McpError::CombinedToolLimit { limit: 1 })
        ));
        assert_eq!(registry.specs().len(), before);
        assert!(!format!("{error:#}").contains(secret_shaped));
    }

    #[test]
    fn startup_diagnostic_does_not_reflect_peer_secret_or_terminal_controls() {
        let secret = "opaque-secret\u{1b}[2J";
        let error = iteron_mcp::McpError::Server {
            code: -32_001,
            message: secret.into(),
        };
        let line = startup_error_line("alpha", "list_tools", &error);
        assert_eq!(
            line,
            "mcp alpha: list_tools failed: MCP server returned error code -32001"
        );
        assert!(!line.contains(secret));
        assert!(!line.contains('\u{1b}'));
    }
}
