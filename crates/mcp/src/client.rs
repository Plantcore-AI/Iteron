//! The async stdio MCP client: spawn a server, initialize, list tools, call tools.

use crate::{
    MAX_FRAME_BYTES, McpError, encode_frame,
    evidence::{DispatchClock, McpToolCallEvidence},
    pagination::ToolListLimits,
    policy::McpServerPolicy,
    request,
    tool_filter::{McpToolFilter, validate_bare_tool_name},
};
use core_protocol::{ToolSpec, capability_set::CapabilitySet};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};
use tokio::sync::Mutex;

mod content;
mod discovery;
mod lifecycle;
mod managed_connect;
mod transport;
pub(crate) use content::{render_extension_content, render_tool_content};
use lifecycle::OwnedProcess;
#[cfg(test)]
use transport::read_frame;
use transport::{ResponseLimits, read_matching_response};

/// Certainty of one `tools/call` exchange. A matching server response is a completed attempt even
/// when the server reports `isError`; transport/protocol loss after dispatch is `Unknown` because
/// the remote process may already have applied the effect.
#[derive(Debug)]
pub enum McpToolOutcome {
    Completed {
        content: String,
        is_error: bool,
        evidence: McpToolCallEvidence,
    },
    FailedDefinite {
        error: McpError,
        /// `None` means validation/serialization failed before any bytes could be dispatched.
        evidence: Option<McpToolCallEvidence>,
    },
    Unknown {
        error: McpError,
        evidence: McpToolCallEvidence,
    },
}

enum CallOutcome {
    Completed(Result<Value, McpError>, Option<std::num::NonZeroU64>),
    Unknown(McpError, std::num::NonZeroU64),
}

/// A connected MCP server. Owns the child process and its stdio.
pub struct McpClient {
    process: Option<OwnedProcess>,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    /// Serialize the complete write/read exchange. Separate stdin/stdout locks are insufficient:
    /// two callers could otherwise consume and discard each other's response IDs.
    calls: Mutex<()>,
    next_id: std::sync::atomic::AtomicU64,
    request_timeout: Duration,
    deadlines: crate::McpTransportDeadlines,
    result_policy: crate::McpResultPolicy,
    spill_store: crate::result_policy::McpSpillStore,
    negotiated_protocol_version: Option<String>,
    capabilities: crate::McpServerCapabilities,
    pub server_name: String,
}

impl McpClient {
    /// Spawn `command args...` as an MCP server and complete the initialize handshake.
    pub async fn connect(command: &str, args: &[String], name: &str) -> Result<Self, McpError> {
        let deadlines = crate::McpDeadlinePolicy::default().stdio();
        Self::connect_with_deadlines(
            command,
            args,
            name,
            deadlines.startup(),
            deadlines.tool_call(),
        )
        .await
    }

    /// Protocol version selected during the completed initialize handshake.
    pub fn negotiated_protocol_version(&self) -> &str {
        self.negotiated_protocol_version
            .as_deref()
            .expect("McpClient is returned only after protocol negotiation")
    }

    pub fn capabilities(&self) -> crate::McpServerCapabilities {
        self.capabilities
    }

    pub fn deadlines(&self) -> crate::McpTransportDeadlines {
        self.deadlines
    }

    pub fn result_policy(&self) -> crate::McpResultPolicy {
        self.result_policy
    }

    /// Install the immutable session result policy before discovery or a tool call. The spill
    /// store remains owned by this connection and is cleaned with it; reconnecting creates a new
    /// store under the same compiled caps.
    pub(crate) fn set_result_policy(&mut self, policy: crate::McpResultPolicy) {
        self.result_policy = policy;
    }

    /// Apply an owning lifecycle boundary to this connection's private result store.
    pub fn cleanup_spills(&self, boundary: crate::McpSpillCleanup) -> Result<(), McpError> {
        self.spill_store
            .cleanup(self.result_policy.cleanup(), boundary)
    }

    /// Invoke the standard resource/prompt surface under the same correlated response bounds.
    pub async fn call_extension(&self, method: &str, params: Value) -> Result<Value, McpError> {
        match method {
            "resources/list" | "resources/read" if self.capabilities.resources => {}
            "prompts/list" | "prompts/get" if self.capabilities.prompts => {}
            _ => return Err(McpError::Protocol("MCP capability is not declared".into())),
        }
        self.call(method, params).await
    }

    pub async fn call_extension_rendered(
        &self,
        method: &str,
        params: Value,
    ) -> Result<String, McpError> {
        let result = self.call_extension(method, params).await?;
        let content = render_extension_content(&result, self.result_policy, &self.spill_store)?;
        self.cleanup_spills(crate::McpSpillCleanup::ToolEnd)?;
        Ok(content)
    }

    /// Invoke a resource/prompt request without erasing post-dispatch uncertainty. Extension
    /// methods are read-only by protocol, but the registry still needs the same exact dispatch
    /// evidence and reconnect refusal as a tool call so it never guesses about a lost response.
    pub async fn call_extension_outcome_observed<F>(
        &self,
        method: &str,
        params: Value,
        on_dispatch: F,
    ) -> McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        match method {
            "resources/list" | "resources/read" if self.capabilities.resources => {}
            "prompts/list" | "prompts/get" if self.capabilities.prompts => {}
            _ => {
                return McpToolOutcome::FailedDefinite {
                    error: McpError::Protocol("MCP capability is not declared".into()),
                    evidence: None,
                };
            }
        }
        let (result, latency) = match self
            .call_with_certainty_and_dispatch_observer(
                method,
                params,
                format!("request `{method}`"),
                Some(Box::new(on_dispatch)),
            )
            .await
        {
            CallOutcome::Completed(Ok(result), Some(latency)) => (result, latency),
            CallOutcome::Completed(Ok(_), None) => {
                return McpToolOutcome::FailedDefinite {
                    error: McpError::Protocol(
                        "MCP extension completed without dispatch evidence".into(),
                    ),
                    evidence: None,
                };
            }
            CallOutcome::Completed(Err(error), latency) => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: latency.map(|latency| {
                        McpToolCallEvidence::new(&self.server_name, method, latency)
                    }),
                };
            }
            CallOutcome::Unknown(error, latency) => {
                return McpToolOutcome::Unknown {
                    error,
                    evidence: McpToolCallEvidence::new(&self.server_name, method, latency),
                };
            }
        };
        let evidence = McpToolCallEvidence::new(&self.server_name, method, latency);
        match render_extension_content(&result, self.result_policy, &self.spill_store) {
            Ok(content) => match self.cleanup_spills(crate::McpSpillCleanup::ToolEnd) {
                Ok(()) => McpToolOutcome::Completed {
                    content,
                    is_error: false,
                    evidence,
                },
                Err(error) => McpToolOutcome::FailedDefinite {
                    error,
                    evidence: Some(evidence),
                },
            },
            Err(error) => McpToolOutcome::FailedDefinite {
                error,
                evidence: Some(evidence),
            },
        }
    }

    /// Connect while removing the caller's exact credential-variable names from the helper
    /// environment. MCP servers are trusted configuration, but are not pricing authorities.
    pub async fn connect_with_sensitive_env_names(
        command: &str,
        args: &[String],
        name: &str,
        sensitive_env_names: &[String],
    ) -> Result<Self, McpError> {
        let deadlines = crate::McpDeadlinePolicy::default().stdio();
        Self::connect_with_deadlines_and_sensitive_env_names(
            command,
            args,
            name,
            deadlines.startup(),
            deadlines.tool_call(),
            sensitive_env_names,
        )
        .await
    }

    async fn connect_with_deadlines(
        command: &str,
        args: &[String],
        name: &str,
        handshake_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, McpError> {
        Self::connect_with_deadlines_and_sensitive_env_names(
            command,
            args,
            name,
            handshake_timeout,
            request_timeout,
            &[],
        )
        .await
    }

    async fn connect_with_deadlines_and_sensitive_env_names(
        command: &str,
        args: &[String],
        name: &str,
        handshake_timeout: Duration,
        request_timeout: Duration,
        sensitive_env_names: &[String],
    ) -> Result<Self, McpError> {
        managed_connect::connect(
            command,
            args,
            name,
            handshake_timeout,
            request_timeout,
            sensitive_env_names,
            None,
        )
        .await
    }

    pub(crate) async fn connect_managed(
        command: &str,
        args: &[String],
        name: &str,
        handshake_timeout: Duration,
        request_timeout: Duration,
        sensitive_env_names: &[String],
        cancellation: &crate::supervisor::McpCancellation,
    ) -> Result<Self, McpError> {
        managed_connect::connect(
            command,
            args,
            name,
            handshake_timeout,
            request_timeout,
            sensitive_env_names,
            Some(cancellation),
        )
        .await
    }

    pub(crate) async fn terminate(&mut self) {
        if let Some(mut process) = self.process.take() {
            process.terminate_and_reap().await;
        }
    }

    pub(crate) fn terminate_sync(&mut self) {
        if let Some(mut process) = self.process.take() {
            process.force_cleanup_sync();
        }
    }

    pub(crate) fn reconcile_liveness(&mut self) -> Result<bool, McpError> {
        match self.process.as_mut() {
            Some(process) => process
                .reconcile_liveness()
                .map_err(|error| McpError::Io(error.to_string())),
            None => Ok(false),
        }
    }

    async fn send_line_unbounded_by_outer_deadline(&self, line: String) -> Result<(), McpError> {
        let dispatch_clock = DispatchClock::default();
        self.send_line_tracking_dispatch(line, &dispatch_clock)
            .await
    }

    async fn send_line_tracking_dispatch(
        &self,
        line: String,
        dispatch_clock: &DispatchClock,
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
        dispatch_clock.mark_dispatched();
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

    pub(crate) async fn notify_unbounded_by_outer_deadline(
        &self,
        method: &str,
        params: Value,
    ) -> Result<(), McpError> {
        let line = encode_frame(&json!({"jsonrpc":"2.0","method":method,"params":params}))?;
        self.send_line_unbounded_by_outer_deadline(line).await
    }

    /// The per-exchange deadline this client applies. Read by the transport seam so a caller that
    /// arrives through `McpWire` inherits the same bound as a caller that arrives inherently.
    pub(crate) fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Send a request and read response lines until the matching id arrives (skipping any
    /// interleaved notifications the server may emit). The deadline covers the complete exchange,
    /// including request serialization/write and lock acquisition.
    pub(crate) async fn call(&self, method: &str, params: Value) -> Result<Value, McpError> {
        let operation = format!("request `{method}`");
        match self
            .call_with_certainty(method, params, operation.clone())
            .await
        {
            CallOutcome::Completed(result, _) => result,
            CallOutcome::Unknown(error, _) => Err(error),
        }
    }

    async fn call_with_certainty(
        &self,
        method: &str,
        params: Value,
        operation: String,
    ) -> CallOutcome {
        self.call_with_certainty_and_dispatch_observer(method, params, operation, None)
            .await
    }

    async fn call_with_certainty_and_dispatch_observer(
        &self,
        method: &str,
        params: Value,
        operation: String,
        dispatch_observer: Option<Box<dyn FnOnce() + Send>>,
    ) -> CallOutcome {
        let dispatch_clock = DispatchClock::with_observer(dispatch_observer);
        match tokio::time::timeout(
            self.request_timeout,
            self.call_unbounded_with_certainty(method, params, &dispatch_clock),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => match dispatch_clock.elapsed_ms() {
                Some(latency) => CallOutcome::Unknown(McpError::Deadline { operation }, latency),
                None => CallOutcome::Completed(Err(McpError::Deadline { operation }), None),
            },
        }
    }

    async fn call_unbounded_by_outer_deadline(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, McpError> {
        let dispatch_clock = DispatchClock::default();
        match self
            .call_unbounded_with_certainty(method, params, &dispatch_clock)
            .await
        {
            CallOutcome::Completed(result, _) => result,
            CallOutcome::Unknown(error, _) => Err(error),
        }
    }

    async fn call_unbounded_with_certainty(
        &self,
        method: &str,
        params: Value,
        dispatch_clock: &DispatchClock,
    ) -> CallOutcome {
        let _call = self.calls.lock().await;
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let line = match request(id, method, params) {
            Ok(line) => line,
            Err(error) => return CallOutcome::Completed(Err(error), None),
        };
        if let Err(error) = self.send_line_tracking_dispatch(line, dispatch_clock).await {
            return CallOutcome::Unknown(
                error,
                dispatch_clock
                    .elapsed_ms()
                    .expect("the writer marks dispatch before its first fallible write"),
            );
        }
        let mut reader = self.stdout.lock().await;
        match read_matching_response(&mut *reader, id, ResponseLimits::default()).await {
            Ok(value) => CallOutcome::Completed(Ok(value), dispatch_clock.elapsed_ms()),
            // A matching JSON-RPC error response is an authoritative remote terminal. Every
            // framing/EOF/parse failure after the write remains unknown.
            Err(error @ McpError::Server { .. }) => {
                CallOutcome::Completed(Err(error), dispatch_clock.elapsed_ms())
            }
            Err(error) => CallOutcome::Unknown(
                error,
                dispatch_clock
                    .elapsed_ms()
                    .expect("a response read only begins after dispatch"),
            ),
        }
    }

    /// Discover tools. Each MCP tool becomes a bounded `ToolSpec` with UNTRUSTED defaults
    /// (ADR-007 R16): `Effecting` capability (never early-dispatched), and a description scanned
    /// for injection before UTF-8-safe truncation.
    pub async fn list_tools(&self) -> Result<Vec<ToolSpec>, McpError> {
        self.list_tools_filtered(&McpToolFilter::default()).await
    }

    /// Discover only tools admitted by an exact per-server operator filter. Filtering occurs
    /// before excluded descriptions and schemas consume the retained catalog budget.
    pub async fn list_tools_filtered(
        &self,
        filter: &McpToolFilter,
    ) -> Result<Vec<ToolSpec>, McpError> {
        filter.validate()?;
        discovery::list_tools(self, ToolListLimits::default(), filter.clone()).await
    }

    /// Discover tools admitted by both the name filter and the authority policy.
    ///
    /// `host_ceiling` is the authority the composition root is willing to admit for this server.
    /// The server's own policy can only narrow it further, so installing a server can never widen
    /// what the host allows; a tool whose class does not survive is never exposed at all.
    pub async fn list_tools_governed(
        &self,
        filter: &McpToolFilter,
        policy: &McpServerPolicy,
        host_ceiling: CapabilitySet,
    ) -> Result<Vec<ToolSpec>, McpError> {
        filter.validate()?;
        policy.validate()?;
        discovery::list_tools_governed(
            self,
            ToolListLimits::default(),
            filter.clone(),
            policy.clone(),
            host_ceiling,
        )
        .await
    }

    #[cfg(test)]
    async fn list_tools_with_limits(
        &self,
        limits: ToolListLimits,
    ) -> Result<Vec<ToolSpec>, McpError> {
        discovery::list_tools(self, limits, McpToolFilter::default()).await
    }

    /// Call an MCP tool without erasing transport certainty. `name` is the bare server-side name
    /// (not the namespaced spec name).
    pub async fn call_tool_outcome(&self, name: &str, arguments: Value) -> McpToolOutcome {
        self.call_tool_outcome_inner(name, arguments, None).await
    }

    /// Call an MCP tool and notify a local observer at the exact conservative dispatch boundary.
    /// The callback is an in-process composition seam, not a telemetry sink; it runs immediately
    /// before the first fallible pipe write and at most once.
    pub async fn call_tool_outcome_observed<F>(
        &self,
        name: &str,
        arguments: Value,
        on_dispatch: F,
    ) -> McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        self.call_tool_outcome_inner(name, arguments, Some(Box::new(on_dispatch)))
            .await
    }

    async fn call_tool_outcome_inner(
        &self,
        name: &str,
        arguments: Value,
        dispatch_observer: Option<Box<dyn FnOnce() + Send>>,
    ) -> McpToolOutcome {
        if let Err(error) = validate_bare_tool_name(name) {
            return McpToolOutcome::FailedDefinite {
                error,
                evidence: None,
            };
        }
        let (result, latency) = match self
            .call_with_certainty_and_dispatch_observer(
                "tools/call",
                json!({"name": name, "arguments": arguments}),
                "request `tools/call`".into(),
                dispatch_observer,
            )
            .await
        {
            CallOutcome::Completed(Ok(result), Some(latency)) => (result, latency),
            CallOutcome::Completed(Ok(_), None) => {
                return McpToolOutcome::FailedDefinite {
                    error: McpError::Protocol(
                        "tools/call completed without dispatch evidence".into(),
                    ),
                    evidence: None,
                };
            }
            CallOutcome::Completed(Err(error), latency) => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: latency
                        .map(|latency| McpToolCallEvidence::new(&self.server_name, name, latency)),
                };
            }
            CallOutcome::Unknown(error, latency) => {
                return McpToolOutcome::Unknown {
                    error,
                    evidence: McpToolCallEvidence::new(&self.server_name, name, latency),
                };
            }
        };
        let evidence = McpToolCallEvidence::new(&self.server_name, name, latency);
        // Preserve text and make every unsupported block observable without reflecting its
        // untrusted type/payload. The renderer enforces one total output ceiling.
        let output = match render_tool_content(&result, self.result_policy, &self.spill_store) {
            Ok(output) => output,
            Err(error) => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: Some(evidence),
                };
            }
        };
        if let Err(error) = self.cleanup_spills(crate::McpSpillCleanup::ToolEnd) {
            return McpToolOutcome::FailedDefinite {
                error,
                evidence: Some(evidence),
            };
        }
        McpToolOutcome::Completed {
            content: output,
            is_error: result
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            evidence,
        }
    }

    /// Compatibility projection for callers that cannot preserve certainty. Runtime tool wiring
    /// must use [`McpClient::call_tool_outcome`].
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<String, McpError> {
        match self.call_tool_outcome(name, arguments).await {
            McpToolOutcome::Completed { content, .. } => Ok(content),
            McpToolOutcome::FailedDefinite { error, .. }
            | McpToolOutcome::Unknown { error, .. } => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_version::REQUESTED_PROTOCOL_VERSION;
    use std::process::Stdio;
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
    fn wait_until_gone_sync(pid: u32) -> bool {
        for _ in 0..200 {
            if !process_exists(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[cfg(unix)]
    async fn wait_until_file_exists(path: &std::path::Path) -> bool {
        // Ten seconds, not one. This waits on a real `/bin/bash` being scheduled, reading a line
        // and writing a file; one second is ample on an idle machine and marginal on a box running
        // the whole suite in parallel, which made these tests fail for load rather than for a
        // defect. The loop returns the instant the file appears, so a larger ceiling costs nothing
        // when the code is correct and only buys patience when the machine is busy -- the same
        // class of load-dependent bound as #106/#108.
        for _ in 0..500 {
            if path.is_file() {
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
    #[test]
    fn drop_after_runtime_shutdown_reaps_direct_child_and_descendant() {
        let pid_path = pid_file("drop-without-runtime");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = runtime.block_on(async {
            let args = vec![
                "-c".to_string(),
                concat!(
                    "IFS= read -r init; ",
                    "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
                    "IFS= read -r initialized; sleep 60 & descendant=$!; ",
                    "printf '%s %s' $$ $descendant > \"$1\"; wait"
                )
                .to_string(),
                "mcp-test".to_string(),
                pid_path.to_string_lossy().into_owned(),
            ];
            let client = McpClient::connect_with_deadlines(
                "/bin/bash",
                &args,
                "drop-test",
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
            assert!(wait_until_file_exists(&pid_path).await);
            client
        });
        let pids: Vec<u32> = std::fs::read_to_string(&pid_path)
            .unwrap()
            .split_whitespace()
            .map(|pid| pid.parse().unwrap())
            .collect();
        assert_eq!(pids.len(), 2);
        assert!(pids.iter().all(|pid| process_exists(*pid)));
        drop(runtime);
        drop(client);
        assert!(
            wait_until_gone_sync(pids[0]),
            "direct MCP child {} survived no-runtime Drop",
            pids[0]
        );
        assert!(
            wait_until_gone_sync(pids[1]),
            "MCP descendant {} survived no-runtime Drop",
            pids[1]
        );
        let _ = std::fs::remove_file(pid_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supported_protocol_version_completes_before_initialized_notification() {
        let initialized_path = pid_file("supported-version-initialized");
        let args = vec![
            "-c".to_string(),
            concat!(
                "IFS= read -r init; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\"}}'; ",
                "IFS= read -r initialized; printf '%s' \"$initialized\" > \"$1\"; ",
                "exec sleep 60"
            )
            .to_string(),
            "mcp-test".to_string(),
            initialized_path.to_string_lossy().into_owned(),
        ];
        let mut client = McpClient::connect_with_deadlines(
            "/bin/bash",
            &args,
            "test",
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        assert_eq!(
            client.negotiated_protocol_version(),
            REQUESTED_PROTOCOL_VERSION
        );
        assert!(wait_until_file_exists(&initialized_path).await);
        let initialized = std::fs::read_to_string(&initialized_path).unwrap();
        assert!(initialized.contains("notifications/initialized"));

        client.terminate().await;
        let _ = std::fs::remove_file(initialized_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unknown_protocol_version_refuses_before_initialized_and_reaps_server() {
        let pid_path = pid_file("unsupported-version-pid");
        let initialized_path = pid_file("unsupported-version-initialized");
        let args = vec![
            "-c".to_string(),
            concat!(
                "echo $$ > \"$1\"; IFS= read -r init; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2099-01-01\"}}'; ",
                "if IFS= read -r initialized; then printf '%s' \"$initialized\" > \"$2\"; fi; ",
                "exec sleep 60"
            )
            .to_string(),
            "mcp-test".to_string(),
            pid_path.to_string_lossy().into_owned(),
            initialized_path.to_string_lossy().into_owned(),
        ];
        let error = match McpClient::connect_with_deadlines(
            "/bin/bash",
            &args,
            "test",
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        {
            Ok(mut client) => {
                client.terminate().await;
                panic!("unsupported MCP protocol version unexpectedly connected");
            }
            Err(error) => error,
        };

        assert!(matches!(
            &error,
            McpError::UnsupportedProtocolVersion {
                client_version,
                server_version,
            } if client_version == REQUESTED_PROTOCOL_VERSION && server_version == "2099-01-01"
        ));
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(REQUESTED_PROTOCOL_VERSION));
        assert!(diagnostic.contains("2099-01-01"));
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            wait_until_gone(pid).await,
            "MCP server {pid} was not reaped"
        );
        assert!(
            !initialized_path.exists(),
            "initialized notification crossed an unsupported-version handshake"
        );

        let _ = std::fs::remove_file(pid_path);
        let _ = std::fs::remove_file(initialized_path);
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
            std::env::set_var(
                "CORE_TEST_PRICING_KEY",
                "mcp-pricing-sentinel-must-not-cross",
            );
            std::env::set_var("XDG_CONFIG_HOME", "mcp-allowlist-sentinel-must-not-cross");
        }
        let args = vec![
            "-c".to_string(),
            concat!(
                "printf '%s|%s|%s' \"${CORE_TEST_PRICING_KEY-EMPTY}\" \"${XDG_CONFIG_HOME-EMPTY}\" \"$PWD\" > \"$1\"; ",
                "IFS= read -r init; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
                "IFS= read -r initialized; exec sleep 60"
            )
            .to_string(),
            "mcp-test".to_string(),
            observation_path.to_string_lossy().into_owned(),
        ];
        let sensitive = vec!["CORE_TEST_PRICING_KEY".into(), "XDG_CONFIG_HOME".into()];
        let client = McpClient::connect_with_deadlines_and_sensitive_env_names(
            "/bin/bash",
            &args,
            "test",
            Duration::from_secs(2),
            Duration::from_secs(2),
            &sensitive,
        )
        .await
        .unwrap();
        unsafe {
            std::env::remove_var("CORE_TEST_PRICING_KEY");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let observation = std::fs::read_to_string(&observation_path).unwrap();
        assert_eq!(observation, "EMPTY|EMPTY|/");
        assert!(!observation.contains("sentinel"));
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
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
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
    async fn single_flight_wait_is_excluded_from_attributed_dispatch_latency() {
        let args = vec![
            "-c".to_string(),
            concat!(
                "IFS= read -r init; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
                "IFS= read -r initialized; ",
                "IFS= read -r slow; sleep 0.20; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"slow\"}]}}'; ",
                "IFS= read -r fast; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"fast\"}]}}'; ",
                "exec sleep 60"
            )
            .to_string(),
        ];
        let client = std::sync::Arc::new(
            McpClient::connect_with_deadlines(
                "/bin/bash",
                &args,
                "latency-server",
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap(),
        );

        let (dispatched_tx, dispatched_rx) = tokio::sync::oneshot::channel();
        let slow_client = client.clone();
        let slow = tokio::spawn(async move {
            slow_client
                .call_tool_outcome_observed("slow-tool", json!({}), move || {
                    let _ = dispatched_tx.send(());
                })
                .await
        });
        dispatched_rx.await.unwrap();

        let fast_total_started = std::time::Instant::now();
        let fast = client.call_tool_outcome("fast-tool", json!({})).await;
        let fast_total_ms = fast_total_started.elapsed().as_millis() as u64;
        let McpToolOutcome::Completed {
            content,
            evidence: fast_evidence,
            ..
        } = fast
        else {
            panic!("fast MCP fixture call did not complete");
        };
        let McpToolOutcome::Completed {
            evidence: slow_evidence,
            ..
        } = slow.await.unwrap()
        else {
            panic!("slow MCP fixture call did not complete");
        };

        assert_eq!(content, "fast\n");
        assert_eq!(fast_evidence.server_name, "latency-server");
        assert_eq!(fast_evidence.tool_name, "fast-tool");
        assert!(slow_evidence.dispatch_to_terminal_ms.get() >= 150);
        assert!(fast_total_ms >= 150, "fixture did not create queue wait");
        assert!(
            fast_evidence.dispatch_to_terminal_ms.get() < 100,
            "single-flight queue wait leaked into dispatch latency: total={fast_total_ms}ms evidence={}ms",
            fast_evidence.dispatch_to_terminal_ms
        );
        drop(client);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tool_timeout_after_dispatch_is_reported_unknown() {
        let pid_path = pid_file("tool-outcome-timeout");
        let args = vec![
            "-c".to_string(),
            concat!(
                "IFS= read -r init; ",
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
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
        let dispatch_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = dispatch_count.clone();
        let outcome = client
            .call_tool_outcome_observed("mutate", json!({}), move || {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .await;
        let McpToolOutcome::Unknown { error, evidence } = outcome else {
            panic!("timed-out dispatched tool did not preserve Unknown certainty");
        };
        assert!(matches!(error, McpError::Deadline { .. }));
        assert_eq!(evidence.server_name, "test");
        assert_eq!(evidence.tool_name, "mutate");
        assert!(evidence.dispatch_to_terminal_ms.get() >= 80);
        assert_eq!(dispatch_count.load(std::sync::atomic::Ordering::SeqCst), 1);
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
                "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
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
            McpToolOutcome::FailedDefinite {
                error: McpError::FrameTooLarge { .. },
                evidence: None,
            }
        ));
        drop(client);
    }
}

#[cfg(test)]
mod catalog_tests;
#[cfg(test)]
mod pagination_tests;
