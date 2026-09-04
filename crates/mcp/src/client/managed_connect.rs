//! Cancellable stdio startup kept separate from the already-large client implementation.

use super::{McpClient, lifecycle::OwnedProcess, multiplex::ResponseRouter};
use crate::{
    McpError,
    protocol_version::{
        DiscoveryNegotiation, DiscoveryRejection, MODERN_PROTOCOL_VERSION, McpProtocolMode,
        STATEFUL_REQUESTED_PROTOCOL_VERSION, discover_params, discovery_allows_stateful_fallback,
        discovery_rejection, negotiate_discovery, negotiate_initialize_result,
        require_modern_discovery,
    },
    tool_filter::validate_server_name,
};
use serde_json::json;
use std::{process::Stdio, sync::Arc, time::Duration};
use tokio::{io::BufReader, sync::Mutex};

const READ_BUFFER_BYTES: usize = 8 * 1024;

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect(
    command: &str,
    args: &[String],
    name: &str,
    handshake_timeout: Duration,
    request_timeout: Duration,
    sensitive_env_names: &[String],
    granted_env_names: &[String],
    cancellation: Option<&crate::supervisor::McpCancellation>,
    protocol_mode: McpProtocolMode,
) -> Result<McpClient, McpError> {
    let startup_milliseconds =
        u64::try_from(handshake_timeout.as_millis()).map_err(|_| McpError::InvalidEndpoint {
            field: "startup_deadline",
            limit: crate::MAX_MCP_DEADLINE_MILLISECONDS as usize,
        })?;
    let tool_call_milliseconds =
        u64::try_from(request_timeout.as_millis()).map_err(|_| McpError::InvalidEndpoint {
            field: "tool_deadline",
            limit: crate::MAX_MCP_DEADLINE_MILLISECONDS as usize,
        })?;
    let deadlines = crate::McpTransportDeadlines::new(startup_milliseconds, tool_call_milliseconds)
        .map_err(|_| McpError::InvalidEndpoint {
            field: "deadline",
            limit: crate::MAX_MCP_DEADLINE_MILLISECONDS as usize,
        })?;
    // Reject ambiguous namespaces before granting process authority. Server namespaces cannot
    // contain `_`, so the first `__` in a registered name is an unambiguous separator.
    validate_server_name(name)?;
    let mut command = tokio::process::Command::new(command);
    // A stdio server is trusted user configuration, but it is not entitled to every provider
    // credential injected into Core. Give it only toolchain/locale values plus exact names the
    // operator explicitly granted to this server.
    iteron_sandbox::clear_to_safe_child_env_with_exact(&mut command, sensitive_env_names);
    if granted_env_names.len() > 64
        || granted_env_names.iter().any(|name| {
            name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(McpError::InvalidEndpoint {
            field: "stdio_env_name",
            limit: 64,
        });
    }
    for name in granted_env_names {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    iteron_sandbox::configure_process_group(&mut command);
    #[cfg(unix)]
    command.current_dir("/");
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let child = command
        .spawn()
        .map_err(|error| McpError::Spawn(error.to_string()))?;
    let mut process = OwnedProcess::new(child);

    let Some(stdin) = process.take_stdin() else {
        process.terminate_and_reap().await;
        return Err(McpError::Spawn("no stdin".into()));
    };
    let Some(stdout) = process.take_stdout() else {
        process.terminate_and_reap().await;
        return Err(McpError::Spawn("no stdout".into()));
    };

    let stdin = Arc::new(Mutex::new(stdin));
    let responses = ResponseRouter::spawn(
        BufReader::with_capacity(
            iteron_tunables::param_integer(
                "mcp.client.managed_connect.read_buffer_bytes",
                READ_BUFFER_BYTES,
            ),
            stdout,
        ),
        Arc::clone(&stdin),
    );
    let mut client = McpClient {
        process: Some(process),
        stdin,
        responses,
        next_id: std::sync::atomic::AtomicU64::new(1),
        request_timeout,
        deadlines,
        result_policy: crate::McpResultPolicy::default(),
        spill_store: crate::result_policy::McpSpillStore::create()?,
        negotiated_protocol_version: None,
        capabilities: crate::McpServerCapabilities::default(),
        protocol_mode,
        list_cache: crate::cache::McpListCache::new(),
        server_name: name.to_string(),
    };

    // One deadline covers both handshake messages, their writes, lock acquisition, and the
    // initialize response. On every failure path the process is explicitly killed and reaped.
    let handshake = async {
        let mut stateful_request_version = STATEFUL_REQUESTED_PROTOCOL_VERSION.to_owned();
        if protocol_mode.prefers_modern() {
            let mut discovery = client
                .call_unbounded_by_outer_deadline("server/discover", discover_params())
                .await;
            if matches!(
                discovery.as_ref().err().and_then(discovery_rejection),
                Some(DiscoveryRejection::RetryModern)
            ) {
                discovery = client
                    .call_unbounded_by_outer_deadline("server/discover", discover_params())
                    .await;
            }
            let negotiation = match discovery {
                Ok(result) => negotiate_discovery(&result)?,
                Err(error)
                    if protocol_mode == McpProtocolMode::Auto
                        && matches!(
                            discovery_rejection(&error),
                            Some(DiscoveryRejection::Stateful(_))
                        ) =>
                {
                    let Some(DiscoveryRejection::Stateful(version)) = discovery_rejection(&error)
                    else {
                        unreachable!("guard requires a stateful discovery rejection")
                    };
                    DiscoveryNegotiation::Stateful(version)
                }
                Err(error)
                    if protocol_mode == McpProtocolMode::Auto
                        && discovery_allows_stateful_fallback(&error) =>
                {
                    DiscoveryNegotiation::Stateful(STATEFUL_REQUESTED_PROTOCOL_VERSION.to_owned())
                }
                Err(error) => return Err(error),
            };
            match negotiation {
                DiscoveryNegotiation::Modern(version, capabilities) => {
                    client.negotiated_protocol_version = Some(version);
                    client.capabilities = capabilities;
                    client.protocol_mode = McpProtocolMode::Stateless2026;
                    return Ok(());
                }
                legacy @ DiscoveryNegotiation::Stateful(_)
                    if protocol_mode == McpProtocolMode::Stateless2026 =>
                {
                    require_modern_discovery(legacy)?;
                    unreachable!("strict modern negotiation cannot select a stateful version")
                }
                DiscoveryNegotiation::Stateful(version) => {
                    stateful_request_version = version;
                }
            }
        }
        let initialize_result = client
            .call_unbounded_by_outer_deadline(
                "initialize",
                json!({
                    "protocolVersion": stateful_request_version,
                    "capabilities": {},
                    "clientInfo": {"name": "iteron", "version": env!("CARGO_PKG_VERSION")}
                }),
            )
            .await?;
        client.negotiated_protocol_version = Some(negotiate_initialize_result(&initialize_result)?);
        let capabilities = initialize_result
            .get("capabilities")
            .and_then(serde_json::Value::as_object);
        client.capabilities = crate::McpServerCapabilities {
            tools: capabilities.is_some_and(|value| value.contains_key("tools")),
            resources: capabilities.is_some_and(|value| value.contains_key("resources")),
            prompts: capabilities.is_some_and(|value| value.contains_key("prompts")),
        };
        client.protocol_mode = McpProtocolMode::Stateful;
        client
            .notify_unbounded_by_outer_deadline("notifications/initialized", json!({}))
            .await
    };

    enum HandshakeResult {
        Completed(Result<(), McpError>),
        TimedOut,
        Cancelled,
    }
    let result = if let Some(cancellation) = cancellation {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => HandshakeResult::Cancelled,
            result = tokio::time::timeout(handshake_timeout, handshake) => match result {
                Ok(result) => HandshakeResult::Completed(result),
                Err(_) => HandshakeResult::TimedOut,
            },
        }
    } else {
        match tokio::time::timeout(handshake_timeout, handshake).await {
            Ok(result) => HandshakeResult::Completed(result),
            Err(_) => HandshakeResult::TimedOut,
        }
    };
    match result {
        HandshakeResult::Completed(Ok(())) => Ok(client),
        HandshakeResult::Completed(Err(error)) => {
            client.terminate().await;
            Err(error)
        }
        HandshakeResult::TimedOut => {
            client.terminate().await;
            Err(McpError::Deadline {
                operation: format!("{MODERN_PROTOCOL_VERSION} discovery/initialize handshake"),
            })
        }
        HandshakeResult::Cancelled => {
            client.terminate().await;
            Err(McpError::Cancelled {
                operation: "initialize handshake",
            })
        }
    }
}
