//! Trusted-user MCP composition and registry wiring.

use crate::config::McpServerConfig;
use core_protocol::ToolSpec;
use core_tools::Registry;
use std::collections::BTreeSet;
use std::sync::Arc;

struct DiscoveredServer {
    client: Arc<core_mcp::McpClient>,
    name: String,
    specs: Vec<ToolSpec>,
}

/// Connect, filter, globally bound, and then register trusted-user MCP servers.
///
/// Discovery is staged before any registry mutation. A combined-catalog overflow or namespaced
/// collision therefore fails startup without leaving a partially exposed MCP batch.
pub(crate) async fn register_configured_servers(
    registry: &mut Registry,
    servers: &[McpServerConfig],
    sensitive_env_names: &[String],
) -> anyhow::Result<()> {
    register_configured_servers_with_limit(
        registry,
        servers,
        sensitive_env_names,
        core_mcp::MAX_COMBINED_MCP_TOOLS,
    )
    .await
}

async fn register_configured_servers_with_limit(
    registry: &mut Registry,
    servers: &[McpServerConfig],
    sensitive_env_names: &[String],
    combined_limit: usize,
) -> anyhow::Result<()> {
    let mut combined = core_mcp::CombinedToolCatalog::with_limit(combined_limit)?;
    let mut discovered = Vec::with_capacity(servers.len());

    for server in servers {
        match core_mcp::McpClient::connect_with_sensitive_env_names(
            &server.command,
            &server.args,
            &server.name,
            sensitive_env_names,
        )
        .await
        {
            Ok(client) => {
                let client = Arc::new(client);
                match client.list_tools_filtered(&server.tools).await {
                    Ok(specs) => {
                        combined.admit(&specs)?;
                        discovered.push(DiscoveredServer {
                            client,
                            name: server.name.clone(),
                            specs,
                        });
                    }
                    Err(error) => {
                        let diagnostic = startup_error_line(&server.name, "list_tools", &error);
                        eprintln!("{diagnostic}");
                    }
                }
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
        .any(|spec| existing.contains(&spec.name))
    {
        return Err(core_mcp::McpError::ToolNameCollision.into());
    }

    for server in discovered {
        let exposed = server.specs.len();
        for spec in server.specs {
            register_mcp_tool(registry, server.client.clone(), &server.name, spec).map_err(
                |_| anyhow::anyhow!("MCP tool registration failed after bounded preflight"),
            )?;
        }
        eprintln!("mcp: connected `{}` ({exposed} exposed tools)", server.name);
    }
    Ok(())
}

fn startup_error_line(server_name: &str, operation: &str, error: &core_mcp::McpError) -> String {
    format!(
        "mcp {server_name}: {operation} failed: {}",
        error.public_summary()
    )
}

pub(crate) fn register_mcp_tool(
    registry: &mut Registry,
    client: Arc<core_mcp::McpClient>,
    server_name: &str,
    spec: ToolSpec,
) -> Result<(), core_tools::ToolError> {
    let prefix = format!("{server_name}__");
    let bare = spec.name.strip_prefix(&prefix).ok_or_else(|| {
        core_tools::ToolError::Registration(
            "MCP tool does not match its validated server namespace".into(),
        )
    })?;
    let attribution = core_tools::McpEffectAttribution::new(server_name, bare.to_string());
    let bare = bare.to_string();
    registry.register_mcp_effect(spec, attribution, move |call, _root, dispatch_clock| {
        let client = client.clone();
        let bare = bare.clone();
        core_tools::effectfut::box_it(async move {
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
    outcome: core_mcp::McpToolOutcome,
) -> core_tools::ToolExecution {
    match outcome {
        core_mcp::McpToolOutcome::Completed {
            content,
            is_error,
            evidence,
        } => core_tools::ToolExecution::Definite(core_protocol::ToolResult {
            tool_use_id,
            content,
            is_error,
            trust: core_protocol::Trust::Untrusted,
            latency_ms: evidence.dispatch_to_terminal_ms.get(),
        }),
        core_mcp::McpToolOutcome::FailedDefinite { error, evidence } => {
            core_tools::ToolExecution::Definite(core_protocol::ToolResult {
                tool_use_id,
                content: format!("mcp error: {}", error.public_summary()),
                is_error: true,
                trust: core_protocol::Trust::Untrusted,
                latency_ms: evidence
                    .map(|evidence| evidence.dispatch_to_terminal_ms.get())
                    .unwrap_or(0),
            })
        }
        core_mcp::McpToolOutcome::Unknown { evidence, .. } => {
            core_tools::ToolExecution::Unknown(core_protocol::ToolResult {
                tool_use_id,
                content: "MCP request was dispatched but no authoritative terminal response was observed; remote outcome is unknown and Core will not retry it automatically".into(),
                is_error: true,
                trust: core_protocol::Trust::Untrusted,
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
        let response = json!({"jsonrpc":"2.0","id":2,"result":{"tools":tools}}).to_string();
        let script = format!("{HANDSHAKE}printf '%s\\n' \"$1\"; exec sleep 60");
        json!({
            "name": name,
            "command": "/bin/bash",
            "args": ["-c", script, "mcp-fixture", response],
            "tools": filter
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
            error.downcast_ref::<core_mcp::McpError>(),
            Some(core_mcp::McpError::CombinedToolLimit { limit: 1 })
        ));
        assert_eq!(registry.specs().len(), before);
        assert!(!format!("{error:#}").contains(secret_shaped));
    }

    #[test]
    fn startup_diagnostic_does_not_reflect_peer_secret_or_terminal_controls() {
        let secret = "opaque-secret\u{1b}[2J";
        let error = core_mcp::McpError::Server {
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
