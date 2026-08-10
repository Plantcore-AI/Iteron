//! Cancellable stdio startup kept separate from the already-large client implementation.

use super::{McpClient, lifecycle::OwnedProcess};
use crate::{
    McpError,
    protocol_version::{REQUESTED_PROTOCOL_VERSION, negotiate_initialize_result},
    tool_filter::validate_server_name,
};
use serde_json::json;
use std::{process::Stdio, time::Duration};
use tokio::{io::BufReader, sync::Mutex};

const READ_BUFFER_BYTES: usize = 8 * 1024;

pub(super) async fn connect(
    command: &str,
    args: &[String],
    name: &str,
    handshake_timeout: Duration,
    request_timeout: Duration,
    sensitive_env_names: &[String],
    cancellation: Option<&crate::supervisor::McpCancellation>,
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
    // credential injected into Core. Give it only a toolchain/locale environment; explicit
    // per-server secret grants require a future credential broker.
    core_sandbox::clear_to_safe_child_env_with_exact(&mut command, sensitive_env_names);
    core_sandbox::configure_process_group(&mut command);
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

    let mut client = McpClient {
        process: Some(process),
        stdin: Mutex::new(stdin),
        stdout: Mutex::new(BufReader::with_capacity(READ_BUFFER_BYTES, stdout)),
        calls: Mutex::new(()),
        next_id: std::sync::atomic::AtomicU64::new(1),
        request_timeout,
        deadlines,
        result_policy: crate::McpResultPolicy::default(),
        spill_store: crate::result_policy::McpSpillStore::create()?,
        negotiated_protocol_version: None,
        capabilities: crate::McpServerCapabilities::default(),
        server_name: name.to_string(),
    };

    // One deadline covers both handshake messages, their writes, lock acquisition, and the
    // initialize response. On every failure path the process is explicitly killed and reaped.
    let handshake = async {
        let initialize_result = client
            .call_unbounded_by_outer_deadline(
                "initialize",
                json!({
                    "protocolVersion": REQUESTED_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "core", "version": env!("CARGO_PKG_VERSION")}
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
                operation: "initialize handshake".into(),
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
