//! Thin executable adapter for the pinned upstream MCP client conformance suite.

use iteron_mcp::http::{McpHttpEndpoint, McpHttpHeaderPolicy};
use iteron_mcp::{McpRemoteClient, McpToolOutcome};
use serde_json::Value;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("conformance client failed: {}", error.public_summary());
        std::process::exit(1);
    }
}

async fn run() -> Result<(), iteron_mcp::McpError> {
    let mut arguments = std::env::args().skip(1);
    let target = arguments
        .next()
        .ok_or_else(|| iteron_mcp::McpError::Protocol("conformance URL is required".into()))?;
    if target == "--stdio-smoke" {
        let command = arguments.next().ok_or_else(|| {
            iteron_mcp::McpError::Protocol("stdio conformance command is required".into())
        })?;
        return run_stdio(&command, &arguments.collect::<Vec<_>>()).await;
    }
    let url = target;
    let endpoint = McpHttpEndpoint::parse(&url)?;
    let version =
        std::env::var("ITERON_MCP_PROTOCOL_VERSION").unwrap_or_else(|_| "2026-07-28".into());
    let credential = std::env::var("ITERON_CONFORMANCE_ACCESS_TOKEN")
        .ok()
        .map(|secret| iteron_mcp::token::Token::new(secret, u64::MAX));
    let client = if version == iteron_mcp::MODERN_PROTOCOL_VERSION {
        McpRemoteClient::connect_auto_with_policies_and_elicitation(
            endpoint,
            "conformance".into(),
            credential,
            McpHttpHeaderPolicy::default(),
            Vec::new(),
            None,
            Some(iteron_mcp::elicitation_handler_from_mrtr(Arc::new(
                ApproveInputs,
            ))),
            iteron_mcp::McpDeadlinePolicy::default().http(),
            iteron_mcp::McpResultPolicy::default(),
        )
        .await?
    } else if matches!(version.as_str(), "2025-06-18" | "2025-11-25") {
        McpRemoteClient::connect_with_elicitation(
            endpoint,
            "conformance".into(),
            credential,
            McpHttpHeaderPolicy::default(),
            Vec::new(),
            None,
            Some(Arc::new(DefaultElicitation)),
        )
        .await?
    } else {
        return Err(iteron_mcp::McpError::Protocol(
            "unsupported conformance protocol version".into(),
        ));
    };
    let tools = client
        .list_tools_governed(
            &iteron_mcp::McpToolFilter::default(),
            &iteron_mcp::McpServerPolicy::default(),
            iteron_mcp::default_host_ceiling(),
        )
        .await?;
    let scenario = std::env::var("MCP_CONFORMANCE_SCENARIO").unwrap_or_default();
    let calls = scenario_calls(&scenario)?;
    for (name, arguments) in &calls {
        if scenario == "sep-2322-client-request-state" {
            client
                .call_tool_with_mrtr(name, arguments.clone(), &ApproveInputs)
                .await?;
        } else {
            call(&client, name, arguments.clone()).await?;
        }
    }
    if scenario == "http-standard-headers" {
        let resources = client
            .call_extension("resources/list", serde_json::json!({}))
            .await?;
        if let Some(uri) = resources
            .get("resources")
            .and_then(Value::as_array)
            .and_then(|resources| resources.first())
            .and_then(|resource| resource.get("uri"))
            .and_then(Value::as_str)
        {
            client
                .call_extension("resources/read", serde_json::json!({"uri": uri}))
                .await?;
        }
        let prompts = client
            .call_extension("prompts/list", serde_json::json!({}))
            .await?;
        if let Some(name) = prompts
            .get("prompts")
            .and_then(Value::as_array)
            .and_then(|prompts| prompts.first())
            .and_then(|prompt| prompt.get("name"))
            .and_then(Value::as_str)
        {
            client
                .call_extension("prompts/get", serde_json::json!({"name": name}))
                .await?;
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "protocolVersion": client.negotiated_protocol_version(),
            "toolCount": tools.len(),
            "toolCalls": calls.len()
        })
    );
    Ok(())
}

async fn run_stdio(command: &str, args: &[String]) -> Result<(), iteron_mcp::McpError> {
    let client = iteron_mcp::McpClient::connect_auto(command, args, "conformance").await?;
    let tools = client
        .list_tools_governed(
            &iteron_mcp::McpToolFilter::default(),
            &iteron_mcp::McpServerPolicy::default(),
            iteron_mcp::default_host_ceiling(),
        )
        .await?;
    let rendered = client
        .call_tool("echo", serde_json::json!({"text":"stdio-ok"}))
        .await?;
    if rendered != "stdio-ok\n" {
        return Err(iteron_mcp::McpError::Protocol(
            "stdio safe call returned an unexpected result".into(),
        ));
    }
    let readable_failure = matches!(
        client
            .call_tool("missing_tool", serde_json::json!({}))
            .await,
        Err(iteron_mcp::McpError::Server { code: -32601, .. })
    );
    if !readable_failure {
        return Err(iteron_mcp::McpError::Protocol(
            "stdio fixture did not return the expected JSON-RPC failure".into(),
        ));
    }
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "protocolVersion": client.negotiated_protocol_version(),
            "toolCount": tools.len(),
            "safeCall": true,
            "readableFailure": true
        })
    );
    Ok(())
}

async fn call(
    client: &McpRemoteClient,
    name: &str,
    arguments: Value,
) -> Result<(), iteron_mcp::McpError> {
    match client
        .call_tool_outcome_observed(name, arguments, || {})
        .await
    {
        McpToolOutcome::Completed { .. } => Ok(()),
        McpToolOutcome::FailedDefinite { error, .. } | McpToolOutcome::Unknown { error, .. } => {
            Err(error)
        }
    }
}

fn scenario_calls(scenario: &str) -> Result<Vec<(String, Value)>, iteron_mcp::McpError> {
    let calls = match scenario {
        "tools_call" => vec![("add_numbers".into(), serde_json::json!({"a":2,"b":3}))],
        "elicitation-sep1034-client-defaults" => vec![(
            "test_client_elicitation_defaults".into(),
            serde_json::json!({}),
        )],
        "sse-retry" => vec![("test_reconnection".into(), serde_json::json!({}))],
        "sep-2322-client-request-state" => [
            "test_mrtr_unrelated",
            "test_mrtr_no_result_type",
            "test_mrtr_echo_state",
            "test_mrtr_no_state",
        ]
        .into_iter()
        .map(|name| (name.into(), serde_json::json!({})))
        .collect(),
        "http-standard-headers" => vec![("test_headers".into(), serde_json::json!({}))],
        "http-custom-headers" => return context_calls(),
        "http-invalid-tool-headers" => vec![(
            "valid_tool".into(),
            serde_json::json!({"region":"us-west1"}),
        )],
        "auth/tool-call" => vec![("test-tool".into(), serde_json::json!({}))],
        _ => Vec::new(),
    };
    Ok(calls)
}

struct ApproveInputs;

impl iteron_mcp::McpMrtrHandler for ApproveInputs {
    fn request<'a>(
        &'a self,
        _server_name: &'a str,
        _tool_name: &'a str,
        _request_state: Option<&'a str>,
        requests: Vec<iteron_mcp::McpInputRequest>,
    ) -> iteron_mcp::McpFuture<'a, iteron_mcp::McpInputDecision> {
        Box::pin(async move {
            Ok(iteron_mcp::McpInputDecision::Approve(
                requests
                    .into_iter()
                    .map(|request| {
                        let content = request
                            .schema()
                            .get("properties")
                            .and_then(serde_json::Value::as_object)
                            .map(|properties| {
                                properties
                                    .iter()
                                    .map(|(name, schema)| {
                                        let value = match schema
                                            .get("type")
                                            .and_then(serde_json::Value::as_str)
                                        {
                                            Some("boolean") => serde_json::json!(true),
                                            Some("integer") | Some("number") => {
                                                serde_json::json!(1)
                                            }
                                            Some("array") => serde_json::json!([]),
                                            _ => serde_json::json!("iteron"),
                                        };
                                        (name.clone(), value)
                                    })
                                    .collect::<serde_json::Map<_, _>>()
                            })
                            .map(serde_json::Value::Object)
                            .unwrap_or_else(|| serde_json::json!({}));
                        (request.id().to_owned(), content)
                    })
                    .collect(),
            ))
        })
    }
}

struct DefaultElicitation;

impl iteron_mcp::McpElicitationHandler for DefaultElicitation {
    fn elicit<'a>(
        &'a self,
        _server_name: &'a str,
        request: iteron_mcp::ElicitationRequest,
    ) -> iteron_mcp::McpFuture<'a, iteron_mcp::ElicitationResponse> {
        Box::pin(async move {
            let mut content = serde_json::Map::new();
            if let Some(properties) = request
                .requested_schema()
                .get("properties")
                .and_then(Value::as_object)
            {
                for (name, schema) in properties {
                    if let Some(default) = schema.get("default") {
                        content.insert(name.clone(), default.clone());
                    }
                }
            }
            Ok(iteron_mcp::ElicitationResponse::accept(Value::Object(
                content,
            )))
        })
    }
}

fn context_calls() -> Result<Vec<(String, Value)>, iteron_mcp::McpError> {
    let Some(raw) = std::env::var_os("MCP_CONFORMANCE_CONTEXT") else {
        return Ok(Vec::new());
    };
    if raw.len() > 1024 * 1024 {
        return Err(iteron_mcp::McpError::Protocol(
            "conformance context exceeds its bound".into(),
        ));
    }
    let context: Value = serde_json::from_str(&raw.to_string_lossy())?;
    let Some(calls) = context.get("toolCalls").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if calls.len() > 32 {
        return Err(iteron_mcp::McpError::Protocol(
            "conformance tool-call count exceeds its bound".into(),
        ));
    }
    calls
        .iter()
        .map(|call| {
            let name = call
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    iteron_mcp::McpError::Protocol("invalid conformance tool call".into())
                })?
                .to_owned();
            let arguments = call
                .get("arguments")
                .cloned()
                .filter(Value::is_object)
                .ok_or_else(|| {
                    iteron_mcp::McpError::Protocol("invalid conformance arguments".into())
                })?;
            Ok((name, arguments))
        })
        .collect()
}
