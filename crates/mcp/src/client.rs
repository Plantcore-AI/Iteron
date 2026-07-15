//! The async stdio MCP client: spawn a server, initialize, list tools, call tools.

use crate::{
    MAX_FRAME_BYTES, MAX_RESPONSE_BYTES, MAX_RESPONSE_FRAMES, McpError, encode_frame,
    parse_response, request, suspicious_unicode,
};
use core_protocol::{Capability, Purity, ToolSpec};
use serde_json::{Value, json};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

const PROTOCOL_VERSION: &str = "2024-11-05";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const READ_BUFFER_BYTES: usize = 8 * 1024;

/// Certainty of one `tools/call` exchange. A matching server response is a completed attempt even
/// when the server reports `isError`; transport/protocol loss after dispatch is `Unknown` because
/// the remote process may already have applied the effect.
#[derive(Debug)]
pub enum McpToolOutcome {
    Completed { content: String, is_error: bool },
    FailedDefinite(McpError),
    Unknown(McpError),
}

enum CallOutcome {
    Completed(Result<Value, McpError>),
    Unknown(McpError),
}

#[derive(Clone, Copy)]
struct ResponseLimits {
    frame_bytes: usize,
    aggregate_bytes: usize,
    frames: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            frame_bytes: MAX_FRAME_BYTES,
            aggregate_bytes: MAX_RESPONSE_BYTES,
            frames: MAX_RESPONSE_FRAMES,
        }
    }
}

/// A connected MCP server. Owns the child process and its stdio.
pub struct McpClient {
    child: Option<Child>,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    /// Serialize the complete write/read exchange. Separate stdin/stdout locks are insufficient:
    /// two callers could otherwise consume and discard each other's response IDs.
    calls: Mutex<()>,
    next_id: std::sync::atomic::AtomicU64,
    request_timeout: Duration,
    pub server_name: String,
}

impl McpClient {
    /// Spawn `command args...` as an MCP server and complete the initialize handshake.
    pub async fn connect(command: &str, args: &[String], name: &str) -> Result<Self, McpError> {
        Self::connect_with_deadlines(command, args, name, HANDSHAKE_TIMEOUT, REQUEST_TIMEOUT).await
    }

    async fn connect_with_deadlines(
        command: &str,
        args: &[String],
        name: &str,
        handshake_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, McpError> {
        let mut command = tokio::process::Command::new(command);
        // A stdio server is trusted user configuration, but it is not entitled to every provider
        // credential injected into Core. Give it only a toolchain/locale environment; explicit
        // per-server secret grants require a future credential broker.
        core_sandbox::clear_to_safe_child_env(&mut command);
        core_sandbox::configure_process_group(&mut command);
        #[cfg(unix)]
        command.current_dir("/");
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|e| McpError::Spawn(e.to_string()))?;

        let Some(stdin) = child.stdin.take() else {
            terminate_and_reap(&mut child).await;
            return Err(McpError::Spawn("no stdin".into()));
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_and_reap(&mut child).await;
            return Err(McpError::Spawn("no stdout".into()));
        };

        let mut client = McpClient {
            child: Some(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::with_capacity(READ_BUFFER_BYTES, stdout)),
            calls: Mutex::new(()),
            next_id: std::sync::atomic::AtomicU64::new(1),
            request_timeout,
            server_name: name.to_string(),
        };

        // One deadline covers both handshake messages, their writes, lock acquisition, and the
        // initialize response. On every failure path the process is explicitly killed and reaped.
        let handshake = async {
            client
                .call_unbounded_by_outer_deadline(
                    "initialize",
                    json!({
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "core", "version": "0.0.1"}
                    }),
                )
                .await?;
            client
                .notify_unbounded_by_outer_deadline("notifications/initialized", json!({}))
                .await
        };

        let result = tokio::time::timeout(handshake_timeout, handshake).await;
        match result {
            Ok(Ok(())) => Ok(client),
            Ok(Err(error)) => {
                client.terminate().await;
                Err(error)
            }
            Err(_) => {
                client.terminate().await;
                Err(McpError::Deadline {
                    operation: "initialize handshake".into(),
                })
            }
        }
    }

    async fn terminate(&mut self) {
        if let Some(mut child) = self.child.take() {
            terminate_and_reap(&mut child).await;
        }
    }

    async fn send_line_unbounded_by_outer_deadline(&self, line: String) -> Result<(), McpError> {
        let dispatch_started = AtomicBool::new(false);
        self.send_line_tracking_dispatch(line, &dispatch_started)
            .await
    }

    async fn send_line_tracking_dispatch(
        &self,
        line: String,
        dispatch_started: &AtomicBool,
    ) -> Result<(), McpError> {
        // `line` came from the bounded serializer. Retain the check here so future callers cannot
        // accidentally route an unbounded allocation into the process pipe.
        if line.len() > MAX_FRAME_BYTES {
            return Err(McpError::FrameTooLarge {
                limit: MAX_FRAME_BYTES,
            });
        }
        let mut writer = self.stdin.lock().await;
        // From this point onward any failure is conservatively post-dispatch. A pipe write may be
        // partial even when it returns an error, so only pre-serialization/lock failures are
        // provably not sent.
        dispatch_started.store(true, Ordering::SeqCst);
        writer
            .write_all(line.as_bytes())
            .await
            .map_err(|e| McpError::Io(e.to_string()))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| McpError::Io(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| McpError::Io(e.to_string()))?;
        Ok(())
    }

    async fn notify_unbounded_by_outer_deadline(
        &self,
        method: &str,
        params: Value,
    ) -> Result<(), McpError> {
        let line = encode_frame(&json!({"jsonrpc":"2.0","method":method,"params":params}))?;
        self.send_line_unbounded_by_outer_deadline(line).await
    }

    /// Send a request and read response lines until the matching id arrives (skipping any
    /// interleaved notifications the server may emit). The deadline covers the complete exchange,
    /// including request serialization/write and lock acquisition.
    async fn call(&self, method: &str, params: Value) -> Result<Value, McpError> {
        let operation = format!("request `{method}`");
        match self
            .call_with_certainty(method, params, operation.clone())
            .await
        {
            CallOutcome::Completed(result) => result,
            CallOutcome::Unknown(error) => Err(error),
        }
    }

    async fn call_with_certainty(
        &self,
        method: &str,
        params: Value,
        operation: String,
    ) -> CallOutcome {
        let dispatch_started = AtomicBool::new(false);
        match tokio::time::timeout(
            self.request_timeout,
            self.call_unbounded_with_certainty(method, params, &dispatch_started),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) if dispatch_started.load(Ordering::SeqCst) => {
                CallOutcome::Unknown(McpError::Deadline { operation })
            }
            Err(_) => CallOutcome::Completed(Err(McpError::Deadline { operation })),
        }
    }

    async fn call_unbounded_by_outer_deadline(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, McpError> {
        let dispatch_started = AtomicBool::new(false);
        match self
            .call_unbounded_with_certainty(method, params, &dispatch_started)
            .await
        {
            CallOutcome::Completed(result) => result,
            CallOutcome::Unknown(error) => Err(error),
        }
    }

    async fn call_unbounded_with_certainty(
        &self,
        method: &str,
        params: Value,
        dispatch_started: &AtomicBool,
    ) -> CallOutcome {
        let _call = self.calls.lock().await;
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let line = match request(id, method, params) {
            Ok(line) => line,
            Err(error) => return CallOutcome::Completed(Err(error)),
        };
        if let Err(error) = self
            .send_line_tracking_dispatch(line, dispatch_started)
            .await
        {
            return CallOutcome::Unknown(error);
        }
        let mut reader = self.stdout.lock().await;
        match read_matching_response(&mut *reader, id, ResponseLimits::default()).await {
            Ok(value) => CallOutcome::Completed(Ok(value)),
            // A matching JSON-RPC error response is an authoritative remote terminal. Every
            // framing/EOF/parse failure after the write remains unknown.
            Err(error @ McpError::Server { .. }) => CallOutcome::Completed(Err(error)),
            Err(error) => CallOutcome::Unknown(error),
        }
    }

    /// Discover tools. Each MCP tool becomes a `ToolSpec` with UNTRUSTED defaults (ADR-007 R16):
    /// `Effecting` capability (never early-dispatched), and a description scanned for injection.
    pub async fn list_tools(&self) -> Result<Vec<ToolSpec>, McpError> {
        let result = self.call("tools/list", json!({})).await?;
        let tools = result
            .get("tools")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        let mut specs = Vec::new();
        for tool in tools {
            let name = tool
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            let mut description = tool
                .get("description")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            if suspicious_unicode(&description).is_some() {
                // Do not feed an injection-laden description to the model; neutralize it.
                description = format!("[description withheld: suspicious Unicode] tool `{name}`");
            }
            let input_schema = tool
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| json!({"type":"object"}));
            specs.push(ToolSpec {
                name: format!("{}__{}", self.server_name, name), // namespace to avoid collision
                description,
                input_schema,
                purity: Purity::Effecting, // untrusted: never pure by declaration
                capability: Capability::IrreversibleExternal, // most restrictive until proven
            });
        }
        Ok(specs)
    }

    /// Call an MCP tool without erasing transport certainty. `name` is the bare server-side name
    /// (not the namespaced spec name).
    pub async fn call_tool_outcome(&self, name: &str, arguments: Value) -> McpToolOutcome {
        let result = match self
            .call_with_certainty(
                "tools/call",
                json!({"name": name, "arguments": arguments}),
                "request `tools/call`".into(),
            )
            .await
        {
            CallOutcome::Completed(Ok(result)) => result,
            CallOutcome::Completed(Err(error)) => {
                return McpToolOutcome::FailedDefinite(error);
            }
            CallOutcome::Unknown(error) => return McpToolOutcome::Unknown(error),
        };
        // MCP returns content blocks; concatenate text without allowing the derived allocation to
        // exceed the same explicit ceiling as the source frame.
        let content = result.get("content").and_then(|value| value.as_array());
        let mut output = String::new();
        for block in content.into_iter().flatten() {
            if block.get("type").and_then(|value| value.as_str()) != Some("text") {
                continue;
            }
            let text = block
                .get("text")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let required = text.len().saturating_add(1);
            if required > MAX_FRAME_BYTES.saturating_sub(output.len()) {
                return McpToolOutcome::FailedDefinite(McpError::OutputTooLarge {
                    limit: MAX_FRAME_BYTES,
                });
            }
            output.push_str(text);
            output.push('\n');
        }
        McpToolOutcome::Completed {
            content: output,
            is_error: result
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }
    }

    /// Compatibility projection for callers that cannot preserve certainty. Runtime tool wiring
    /// must use [`McpClient::call_tool_outcome`].
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<String, McpError> {
        match self.call_tool_outcome(name, arguments).await {
            McpToolOutcome::Completed { content, .. } => Ok(content),
            McpToolOutcome::FailedDefinite(error) | McpToolOutcome::Unknown(error) => Err(error),
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };

        // Normal use drops a client inside Tokio. Move the process into a reaper task so drop both
        // kills and waits instead of leaving a Unix zombie. The fallback still requests a kill;
        // Tokio's process driver receives the handle for best-effort orphan reaping.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                terminate_and_reap(&mut child).await;
            });
        } else {
            let _ = child.start_kill();
        }
    }
}

async fn terminate_and_reap(child: &mut Child) {
    core_sandbox::terminate_process_group_and_reap(child).await;
}

/// Read one newline-delimited frame with a hard allocation ceiling. Invalid UTF-8 is handled by
/// the response parser as a typed failure; this layer remains byte-oriented so a hostile peer
/// cannot force incremental `String` growth before validation.
async fn read_frame<R>(reader: &mut R, limit: usize) -> Result<Option<Vec<u8>>, McpError>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::with_capacity(limit.min(READ_BUFFER_BYTES));
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| McpError::Io(e.to_string()))?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(McpError::Protocol("server closed mid-frame".into()))
            };
        }

        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if newline > limit.saturating_sub(frame.len()) {
                return Err(McpError::FrameTooLarge { limit });
            }
            frame.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(Some(frame));
        }

        if available.len() > limit.saturating_sub(frame.len()) {
            return Err(McpError::FrameTooLarge { limit });
        }
        let consumed = available.len();
        frame.extend_from_slice(available);
        reader.consume(consumed);
    }
}

async fn read_matching_response<R>(
    reader: &mut R,
    id: u64,
    limits: ResponseLimits,
) -> Result<Value, McpError>
where
    R: AsyncBufRead + Unpin,
{
    let mut aggregate_bytes = 0usize;
    for _ in 0..limits.frames {
        let frame = read_frame(reader, limits.frame_bytes)
            .await?
            .ok_or_else(|| McpError::Protocol("server closed the stream".into()))?;
        aggregate_bytes =
            aggregate_bytes
                .checked_add(frame.len())
                .ok_or(McpError::ResponseTooLarge {
                    limit: limits.aggregate_bytes,
                })?;
        if aggregate_bytes > limits.aggregate_bytes {
            return Err(McpError::ResponseTooLarge {
                limit: limits.aggregate_bytes,
            });
        }

        let text = std::str::from_utf8(&frame).map_err(|_| McpError::InvalidUtf8)?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed)?;
        if value.get("id").and_then(Value::as_u64) == Some(id) {
            drop(value);
            return parse_response(trimmed);
        }
    }
    Err(McpError::TooManyFrames {
        limit: limits.frames,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    #[tokio::test]
    async fn overlong_frame_without_newline_is_rejected_without_growing_past_limit() {
        let (mut peer, stream) = duplex(128);
        let writer = tokio::spawn(async move {
            let _ = peer.write_all(&[b'x'; 128]).await;
        });
        let mut reader = BufReader::with_capacity(16, stream);
        let error = read_frame(&mut reader, 32).await.unwrap_err();
        assert!(matches!(error, McpError::FrameTooLarge { limit: 32 }));
        drop(reader);
        let _ = writer.await;
    }

    #[tokio::test]
    async fn interleaved_frames_have_aggregate_byte_ceiling() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n";
        let (mut peer, stream) = duplex(input.len());
        peer.write_all(input).await.unwrap();
        drop(peer);
        let mut reader = BufReader::new(stream);
        let limits = ResponseLimits {
            frame_bytes: 128,
            aggregate_bytes: 40,
            frames: 4,
        };
        let error = read_matching_response(&mut reader, 7, limits)
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::ResponseTooLarge { limit: 40 }));
    }

    #[tokio::test]
    async fn empty_frame_flood_has_count_ceiling() {
        let (mut peer, stream) = duplex(8);
        peer.write_all(b"\n\n\n\n").await.unwrap();
        drop(peer);
        let mut reader = BufReader::new(stream);
        let limits = ResponseLimits {
            frame_bytes: 8,
            aggregate_bytes: 8,
            frames: 3,
        };
        let error = read_matching_response(&mut reader, 1, limits)
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::TooManyFrames { limit: 3 }));
    }

    #[tokio::test]
    async fn invalid_utf8_is_a_typed_protocol_failure() {
        let (mut peer, stream) = duplex(8);
        peer.write_all(&[0xff, b'\n']).await.unwrap();
        drop(peer);
        let mut reader = BufReader::new(stream);
        let error = read_matching_response(&mut reader, 1, ResponseLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::InvalidUtf8));
    }

    #[cfg(unix)]
    fn process_exists(pid: u32) -> bool {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[cfg(unix)]
    async fn wait_until_gone(pid: u32) -> bool {
        for _ in 0..50 {
            if !process_exists(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[cfg(unix)]
    fn pid_file(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "core-mcp-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn handshake_timeout_kills_and_reaps_server() {
        let pid_path = pid_file("handshake-timeout");
        let args = vec![
            "-c".to_string(),
            "echo $$ > \"$1\"; exec sleep 60".to_string(),
            "mcp-test".to_string(),
            pid_path.to_string_lossy().into_owned(),
        ];
        let error = match McpClient::connect_with_deadlines(
            "bash",
            &args,
            "test",
            Duration::from_millis(500),
            Duration::from_secs(5),
        )
        .await
        {
            Ok(_) => panic!("unresponsive MCP handshake unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(error, McpError::Deadline { .. }));
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            !process_exists(pid),
            "timed-out MCP server {pid} was not reaped"
        );
        let _ = std::fs::remove_file(pid_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn server_starts_outside_repo_with_default_deny_environment() {
        let observation_path = pid_file("safe-env");
        unsafe {
            std::env::set_var("GATEWAY_KEY", "mcp-sentinel-must-not-cross");
        }
        let args = vec![
            "-c".to_string(),
            concat!(
                "printf '%s|%s' \"${GATEWAY_KEY-EMPTY}\" \"$PWD\" > \"$1\"; ",
                "IFS= read -r init; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'; ",
                "IFS= read -r initialized; exec sleep 60"
            )
            .to_string(),
            "mcp-test".to_string(),
            observation_path.to_string_lossy().into_owned(),
        ];
        let client = McpClient::connect_with_deadlines(
            "/bin/bash",
            &args,
            "test",
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        unsafe {
            std::env::remove_var("GATEWAY_KEY");
        }
        let observation = std::fs::read_to_string(&observation_path).unwrap();
        assert_eq!(observation, "EMPTY|/");
        assert!(!observation.contains("mcp-sentinel"));
        drop(client);
        let _ = std::fs::remove_file(observation_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn request_deadline_and_drop_do_not_leak_server() {
        let pid_path = pid_file("request-timeout");
        let args = vec![
            "-c".to_string(),
            concat!(
                "IFS= read -r init; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'; ",
                "IFS= read -r initialized; echo $$ > \"$1\"; ",
                "IFS= read -r request; exec sleep 60"
            )
            .to_string(),
            "mcp-test".to_string(),
            pid_path.to_string_lossy().into_owned(),
        ];
        let client = McpClient::connect_with_deadlines(
            "bash",
            &args,
            "test",
            Duration::from_secs(2),
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        let error = client.list_tools().await.unwrap_err();
        assert!(matches!(error, McpError::Deadline { .. }));
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        drop(client);
        assert!(
            wait_until_gone(pid).await,
            "dropped MCP server {pid} was not reaped"
        );
        let _ = std::fs::remove_file(pid_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tool_timeout_after_dispatch_is_reported_unknown() {
        let pid_path = pid_file("tool-outcome-timeout");
        let args = vec![
            "-c".to_string(),
            concat!(
                "IFS= read -r init; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'; ",
                "IFS= read -r initialized; echo $$ > \"$1\"; ",
                "IFS= read -r request; exec sleep 60"
            )
            .to_string(),
            "mcp-test".to_string(),
            pid_path.to_string_lossy().into_owned(),
        ];
        let client = McpClient::connect_with_deadlines(
            "/bin/bash",
            &args,
            "test",
            Duration::from_secs(2),
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        let outcome = client.call_tool_outcome("mutate", json!({})).await;
        assert!(matches!(
            outcome,
            McpToolOutcome::Unknown(McpError::Deadline { .. })
        ));
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        drop(client);
        assert!(wait_until_gone(pid).await);
        let _ = std::fs::remove_file(pid_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn oversized_tool_request_is_definite_before_dispatch() {
        let args = vec![
            "-c".to_string(),
            concat!(
                "IFS= read -r init; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'; ",
                "IFS= read -r initialized; exec sleep 60"
            )
            .to_string(),
        ];
        let client = McpClient::connect_with_deadlines(
            "/bin/bash",
            &args,
            "test",
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let outcome = client
            .call_tool_outcome("mutate", Value::String("x".repeat(MAX_FRAME_BYTES)))
            .await;
        assert!(matches!(
            outcome,
            McpToolOutcome::FailedDefinite(McpError::FrameTooLarge { .. })
        ));
        drop(client);
    }
}
