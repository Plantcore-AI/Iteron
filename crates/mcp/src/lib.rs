//! iteron-mcp — a Model Context Protocol client (stdio transport).
//!
//! MCP is the standard tool-ecosystem protocol, and Principal.md embraces the ecosystem at
//! standard protocol layers. This client spawns an MCP server, does the `initialize` handshake,
//! discovers tools (`tools/list`), and calls them (`tools/call`) over newline-delimited
//! JSON-RPC 2.0 on the server's stdin/stdout.
//!
//! SECURITY (ADR-007 R16): MCP-declared purity is UNTRUSTED. An MCP tool defaults to `Effecting`
//! (gated at message_stop + approval), never early-dispatched, until its confinement is
//! evidenced — a third-party server does not get to declare itself pure. Tool descriptions are
//! untrusted content and are scanned for bidi/invisible Unicode, UTF-8-safely truncated, and
//! catalog-budgeted before the model sees them. Names and schemas fail closed at fixed ceilings.
//!
//! What is here: the JSON-RPC framing (pure, unit-tested), the async stdio client, and the
//! mapping from an MCP tool to a `ToolSpec` with the untrusted defaults. Deterministic local stdio
//! fixtures exercise discovery without credentials or an external MCP server.

use serde_json::{Value, json};
use std::io::Write;

pub mod client;
mod elicitation;
mod evidence;
pub mod http;
pub mod oauth;
mod pagination;
mod policy;
mod protocol_version;
pub mod reconnect;
mod remote;
pub mod supervisor;
pub mod token;
mod tool_catalog;
mod tool_filter;
pub mod wire;

pub use client::{McpClient, McpToolOutcome};
pub use elicitation::{
    ElicitationAction, ElicitationRequest, ElicitationResponse, MAX_ELICITATION_CONTENT_BYTES,
    MAX_ELICITATION_FIELD_NAME_BYTES, MAX_ELICITATION_FIELDS, MAX_ELICITATION_MESSAGE_BYTES,
    MAX_ELICITATION_SCHEMA_BYTES, McpElicitationHandler,
};
pub use evidence::McpToolCallEvidence;
pub use policy::{MAX_MCP_TOOL_POLICY_ENTRIES, McpServerPolicy, default_host_ceiling};
pub use remote::{McpRemoteClient, McpServerCapabilities};
pub use tool_filter::{
    CombinedToolCatalog, MAX_COMBINED_MCP_CATALOG_BYTES, MAX_COMBINED_MCP_TOOLS,
    MAX_MCP_BARE_TOOL_NAME_BYTES, MAX_MCP_SERVER_NAME_BYTES, MAX_MCP_TOOL_FILTER_ENTRIES,
    McpToolFilter, validate_server_name,
};
pub use wire::{McpFuture, McpTransportKind, McpWire};

/// Maximum payload size of one newline-delimited JSON-RPC frame, in bytes.
///
/// This applies in both directions. The delimiter is not counted. Keeping the limit here makes
/// the transport's memory contract visible to callers instead of relying on `BufReader` growth.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Maximum aggregate payload accepted while skipping interleaved frames for one response.
pub const MAX_RESPONSE_BYTES: usize = 4 * MAX_FRAME_BYTES;

/// Maximum number of frames inspected while waiting for one matching response.
///
/// A separate count is necessary because a peer can otherwise send an infinite stream of empty
/// lines or tiny notifications without reaching the aggregate byte ceiling.
pub const MAX_RESPONSE_FRAMES: usize = 1024;

/// Maximum number of `tools/list` pages accepted from one discovery pass.
pub const MAX_TOOL_LIST_PAGES: usize = 64;

/// Maximum number of tools accepted across one paginated discovery pass.
pub const MAX_TOOL_LIST_TOOLS: usize = 4096;

/// Maximum cumulative serialized bytes accepted across all `tools/list` results.
pub const MAX_TOOL_LIST_BYTES: usize = 4 * MAX_FRAME_BYTES;

/// Maximum bytes in the final namespaced name of one MCP tool. Oversized names are rejected,
/// never truncated, because truncation could collide two callable identities.
pub const MAX_MCP_TOOL_NAME_BYTES: usize = 256;

/// Maximum UTF-8 bytes retained from one MCP tool description, including its truncation marker.
pub const MAX_MCP_TOOL_DESCRIPTION_BYTES: usize = 2048;

/// Maximum serialized JSON bytes in one MCP input schema. Schemas are rejected rather than
/// truncated because partial JSON Schema has different semantics.
pub const MAX_MCP_TOOL_SCHEMA_BYTES: usize = 64 * 1024;

/// Maximum description bytes retained across one server's complete tool catalog.
pub const MAX_MCP_TOOL_DESCRIPTIONS_BYTES: usize = 64 * 1024;

/// Maximum serialized bytes in the complete retained `ToolSpec` catalog for one MCP server.
pub const MAX_MCP_TOOL_CATALOG_BYTES: usize = 512 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("spawn: {0}")]
    Spawn(String),
    #[error("io: {0}")]
    Io(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("invalid MCP initialize protocolVersion; client supports `{client_version}`")]
    InvalidProtocolVersion { client_version: String },
    #[error(
        "unsupported MCP protocol version: client supports `{client_version}` but server selected `{server_version}`"
    )]
    UnsupportedProtocolVersion {
        client_version: String,
        server_version: String,
    },
    #[error("MCP frame exceeds {limit} byte limit")]
    FrameTooLarge { limit: usize },
    #[error("MCP response frames exceed {limit} aggregate byte limit")]
    ResponseTooLarge { limit: usize },
    #[error("MCP response exceeds {limit} frame limit")]
    TooManyFrames { limit: usize },
    #[error("MCP tool output exceeds {limit} byte limit")]
    OutputTooLarge { limit: usize },
    #[error("MCP tools/list exceeds {limit} page limit")]
    ToolListPageLimit { limit: usize },
    #[error("MCP tools/list exceeds {limit} tool limit")]
    ToolListToolLimit { limit: usize },
    #[error("MCP tools/list exceeds {limit} cumulative byte limit")]
    ToolListByteLimit { limit: usize },
    #[error("MCP tools/list repeated a pagination cursor")]
    ToolListCursorCycle,
    #[error("MCP tool name exceeds {limit} byte limit")]
    ToolNameTooLong { limit: usize },
    #[error("invalid MCP server namespace (expected a lowercase ASCII slug up to {limit} bytes)")]
    InvalidServerName { limit: usize },
    #[error(
        "invalid MCP bare tool name (expected safe ASCII alphanumeric, `_`, `-`, or `.` up to {limit} bytes)"
    )]
    InvalidToolName { limit: usize },
    #[error("invalid MCP tool filter (exact unique safe names; at most {limit} entries)")]
    InvalidToolFilter { limit: usize },
    #[error("invalid MCP tool policy (exact unique safe names; at most {limit} entries)")]
    InvalidToolPolicy { limit: usize },
    #[error("duplicate MCP namespaced tool identity")]
    ToolNameCollision,
    #[error("combined MCP tool catalog exceeds {limit} tool limit")]
    CombinedToolLimit { limit: usize },
    #[error("combined MCP tool catalog exceeds {limit} serialized byte limit")]
    CombinedToolCatalogByteLimit { limit: usize },
    #[error("combined MCP tool limit must be in 1..={maximum}")]
    InvalidCombinedToolLimit { maximum: usize },
    #[error("combined MCP catalog byte limit must be in 2..={maximum}")]
    InvalidCombinedCatalogByteLimit { maximum: usize },
    #[error("MCP tool input schema exceeds {limit} serialized byte limit")]
    ToolSchemaTooLarge { limit: usize },
    #[error("MCP tool descriptions exceed {limit} cumulative byte limit")]
    ToolDescriptionBudgetExceeded { limit: usize },
    #[error("MCP tool catalog exceeds {limit} serialized byte limit")]
    ToolCatalogTooLarge { limit: usize },
    #[error("MCP frame is not valid UTF-8")]
    InvalidUtf8,
    #[error("MCP transport closed before the matching response")]
    TransportClosed,
    #[error("deadline exceeded during {operation}")]
    Deadline { operation: String },
    #[error("MCP operation cancelled during {operation}")]
    Cancelled { operation: &'static str },
    #[error("MCP reconnect attempts exhausted after {attempts} attempts")]
    RetryExhausted { attempts: u32 },
    #[error("invalid MCP reconnect policy field `{field}` (maximum {limit})")]
    InvalidReconnectPolicy { field: &'static str, limit: u64 },
    #[error("MCP reconnect base backoff {base_ms}ms exceeds cap {cap_ms}ms")]
    InvalidReconnectBackoffOrder { base_ms: u64, cap_ms: u64 },
    #[error("stale MCP generation: expected {expected}, received {received}")]
    StaleGeneration { expected: u64, received: u64 },
    #[error("MCP lifecycle generation exhausted")]
    GenerationExhausted,
    #[error("invalid MCP lifecycle transition `{event}` from `{state}`")]
    InvalidLifecycleTransition {
        state: &'static str,
        event: &'static str,
    },
    #[error("invalid MCP launch configuration field `{field}` (limit {limit})")]
    InvalidLaunchConfiguration { field: &'static str, limit: usize },
    #[error("invalid MCP tool search field `{field}` (limit {limit})")]
    InvalidToolSearch { field: &'static str, limit: usize },
    #[error("MCP tool identity is stale or belongs to another server binding")]
    StaleToolIdentity,
    #[error("MCP catalog violates the managed lifecycle contract: {reason}")]
    CatalogContract { reason: &'static str },
    #[error("MCP server lifecycle is stopped")]
    LifecycleStopped,
    #[error("MCP server lifecycle failed terminally")]
    LifecycleFailed,
    #[error("server error {code}: {message}")]
    Server { code: i64, message: String },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The credential a request would have carried is not usable. Raised *before* dispatch, so a
    /// stale credential can never be confused with a revoked one by reading a 401 after the fact.
    #[error("MCP credential is not usable: {0}")]
    Credential(#[from] token::TokenError),
    #[error("invalid MCP HTTP endpoint field `{field}` (limit {limit})")]
    InvalidEndpoint { field: &'static str, limit: usize },
    #[error("MCP HTTP endpoint returned status {status}")]
    HttpStatus { status: u16 },
    /// A 3xx was answered, not followed. The configured endpoint is an authority boundary: a
    /// redirect target chosen by the peer must never receive the bearer credential or the body.
    #[error(
        "MCP HTTP endpoint attempted a redirect to an authority the operator did not configure"
    )]
    HttpRedirectRefused,
    #[error("MCP HTTP response media type is neither JSON nor an event stream")]
    UnsupportedMediaType,
    #[error("MCP HTTP session expired and must be re-initialized")]
    SessionExpired,
    /// The HTTP transport is designed, framed, and unit-tested in this crate, but no HTTP client
    /// is admitted into `iteron-mcp`'s dependency graph, so nothing in-tree can perform the
    /// exchange. Selecting it fails closed rather than silently falling back to stdio.
    #[error("MCP HTTP transport is not available in this build")]
    HttpTransportUnavailable,
}

impl McpError {
    /// Stable diagnostic safe for model/terminal projection.
    ///
    /// Unbounded or unsafe MCP peer strings, OS errors, command paths, and parser detail are
    /// intentionally omitted. Bounded dated protocol versions are retained so an operator can
    /// resolve a version mismatch. The typed error remains available to in-process callers for
    /// control flow and tests.
    pub fn public_summary(&self) -> String {
        match self {
            Self::Spawn(_) => "MCP server spawn failed".into(),
            Self::Io(_) => "MCP transport I/O failed".into(),
            Self::Protocol(_) => "MCP protocol exchange failed".into(),
            Self::InvalidProtocolVersion { .. } => {
                "MCP server returned an invalid protocol version".into()
            }
            Self::UnsupportedProtocolVersion {
                client_version,
                server_version,
            } if protocol_version::is_actionable_version_mismatch(
                client_version,
                server_version,
            ) =>
            {
                format!(
                    "MCP protocol version mismatch: client supports `{client_version}` but server selected `{server_version}`"
                )
            }
            Self::UnsupportedProtocolVersion { .. } => {
                "MCP server selected an unsupported protocol version".into()
            }
            Self::FrameTooLarge { limit } => {
                format!("MCP frame exceeds {limit} byte limit")
            }
            Self::ResponseTooLarge { limit } => {
                format!("MCP response frames exceed {limit} aggregate byte limit")
            }
            Self::TooManyFrames { limit } => {
                format!("MCP response exceeds {limit} frame limit")
            }
            Self::OutputTooLarge { limit } => {
                format!("MCP tool output exceeds {limit} byte limit")
            }
            Self::ToolListPageLimit { limit } => {
                format!("MCP tools/list exceeds {limit} page limit")
            }
            Self::ToolListToolLimit { limit } => {
                format!("MCP tools/list exceeds {limit} tool limit")
            }
            Self::ToolListByteLimit { limit } => {
                format!("MCP tools/list exceeds {limit} cumulative byte limit")
            }
            Self::ToolListCursorCycle => "MCP tools/list repeated a pagination cursor".into(),
            Self::ToolNameTooLong { limit } => {
                format!("MCP tool name exceeds {limit} byte limit")
            }
            Self::InvalidServerName { limit } => {
                format!("invalid MCP server namespace (maximum {limit} bytes)")
            }
            Self::InvalidToolName { limit } => {
                format!("invalid MCP bare tool name (maximum {limit} bytes)")
            }
            Self::InvalidToolFilter { limit } => {
                format!("invalid MCP tool filter (maximum {limit} entries)")
            }
            Self::InvalidToolPolicy { limit } => {
                format!("invalid MCP tool policy (maximum {limit} entries)")
            }
            Self::ToolNameCollision => "duplicate MCP namespaced tool identity".into(),
            Self::CombinedToolLimit { limit } => {
                format!("combined MCP tool catalog exceeds {limit} tool limit")
            }
            Self::CombinedToolCatalogByteLimit { limit } => {
                format!("combined MCP tool catalog exceeds {limit} serialized byte limit")
            }
            Self::InvalidCombinedToolLimit { maximum } => {
                format!("combined MCP tool limit must be in 1..={maximum}")
            }
            Self::InvalidCombinedCatalogByteLimit { maximum } => {
                format!("combined MCP catalog byte limit must be in 2..={maximum}")
            }
            Self::ToolSchemaTooLarge { limit } => {
                format!("MCP tool input schema exceeds {limit} serialized byte limit")
            }
            Self::ToolDescriptionBudgetExceeded { limit } => {
                format!("MCP tool descriptions exceed {limit} cumulative byte limit")
            }
            Self::ToolCatalogTooLarge { limit } => {
                format!("MCP tool catalog exceeds {limit} serialized byte limit")
            }
            Self::InvalidUtf8 => "MCP frame is not valid UTF-8".into(),
            Self::TransportClosed => "MCP transport closed before the matching response".into(),
            Self::Deadline { .. } => "MCP operation deadline exceeded".into(),
            Self::Cancelled { .. } => "MCP operation cancelled".into(),
            Self::RetryExhausted { attempts } => {
                format!("MCP reconnect attempts exhausted after {attempts} attempts")
            }
            Self::InvalidReconnectPolicy { .. } => "invalid MCP reconnect policy".into(),
            Self::InvalidReconnectBackoffOrder { base_ms, cap_ms } => {
                format!("MCP reconnect base backoff {base_ms}ms exceeds cap {cap_ms}ms")
            }
            Self::StaleGeneration { expected, received } => {
                format!("stale MCP generation: expected {expected}, received {received}")
            }
            Self::GenerationExhausted => "MCP lifecycle generation exhausted".into(),
            Self::InvalidLifecycleTransition { .. } => "invalid MCP lifecycle transition".into(),
            Self::InvalidLaunchConfiguration { .. } => "invalid MCP launch configuration".into(),
            Self::InvalidToolSearch { .. } => "invalid MCP tool search".into(),
            Self::StaleToolIdentity => {
                "MCP tool identity is stale or belongs to another server binding".into()
            }
            Self::CatalogContract { .. } => {
                "MCP catalog violates the managed lifecycle contract".into()
            }
            Self::LifecycleStopped => "MCP server lifecycle is stopped".into(),
            Self::LifecycleFailed => "MCP server lifecycle failed terminally".into(),
            Self::Server { code, .. } => format!("MCP server returned error code {code}"),
            Self::Json(_) => "MCP peer returned invalid JSON".into(),
            // `TokenError` is a closed set of repository-owned sentences with one numeric skew;
            // it can carry neither the secret nor peer text, so it is safe to project verbatim.
            Self::Credential(error) => format!("MCP credential is not usable: {error}"),
            // The field name is repository vocabulary, but the endpoint itself is operator
            // configuration whose path may be capability-bearing, so nothing is reflected.
            Self::InvalidEndpoint { .. } => "invalid MCP HTTP endpoint".into(),
            Self::HttpStatus { status } => format!("MCP HTTP endpoint returned status {status}"),
            Self::HttpRedirectRefused => {
                "MCP HTTP endpoint attempted a refused cross-authority redirect".into()
            }
            Self::UnsupportedMediaType => {
                "MCP HTTP response media type is neither JSON nor an event stream".into()
            }
            Self::SessionExpired => "MCP HTTP session expired and must be re-initialized".into(),
            Self::HttpTransportUnavailable => {
                "MCP HTTP transport is not available in this build".into()
            }
        }
    }
}

/// Build a JSON-RPC 2.0 request line (newline-delimited transport).
pub fn request(id: u64, method: &str, params: Value) -> Result<String, McpError> {
    encode_frame(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
}

/// Serialize one outbound frame without ever retaining more than [`MAX_FRAME_BYTES`].
pub(crate) fn encode_frame(value: &Value) -> Result<String, McpError> {
    let mut writer = LimitedWriter::new(MAX_FRAME_BYTES);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.exceeded {
            return Err(McpError::FrameTooLarge {
                limit: MAX_FRAME_BYTES,
            });
        }
        return Err(McpError::Json(error));
    }
    String::from_utf8(writer.bytes).map_err(|_| McpError::InvalidUtf8)
}

/// A serializer sink that refuses the write before its backing allocation can cross the limit.
struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl LimitedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(4096)),
            limit,
            exceeded: false,
        }
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other("MCP frame byte limit exceeded"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Parse a JSON-RPC response line, returning the `result` or a typed server error.
pub fn parse_response(line: &str) -> Result<Value, McpError> {
    let v: Value = serde_json::from_str(line)?;
    if let Some(err) = v.get("error") {
        return Err(McpError::Server {
            code: err.get("code").and_then(|x| x.as_i64()).unwrap_or(0),
            message: err
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        });
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| McpError::Protocol("no result in response".into()))
}

/// Scan a tool description (untrusted) for bidi/invisible Unicode. Returns the bad codepoint if
/// present — an MCP tool description is exactly the injection surface ADR-007 §6 names.
pub fn suspicious_unicode(s: &str) -> Option<u32> {
    s.chars().map(|c| c as u32).find(
        |&c| matches!(c, 0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x00AD | 0xFEFF),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_valid_jsonrpc() {
        let line = request(1, "tools/list", json!({})).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "tools/list");
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn outbound_frame_is_rejected_before_crossing_limit() {
        let oversized = "x".repeat(MAX_FRAME_BYTES);
        let error = request(1, "tools/call", json!({"value": oversized})).unwrap_err();
        assert!(matches!(
            error,
            McpError::FrameTooLarge {
                limit: MAX_FRAME_BYTES
            }
        ));
    }

    #[test]
    fn parse_response_returns_result() {
        let r = parse_response(r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#).unwrap();
        assert!(r.get("tools").is_some());
    }

    #[test]
    fn parse_response_surfaces_server_error() {
        let e = parse_response(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#,
        );
        assert!(matches!(e, Err(McpError::Server { code: -32601, .. })));
    }

    #[test]
    fn public_error_summary_never_reflects_peer_or_terminal_control_text() {
        let secret = "opaque-secret\u{1b}[31m";
        let error = McpError::Server {
            code: -32_001,
            message: secret.into(),
        };
        let summary = error.public_summary();
        assert_eq!(summary, "MCP server returned error code -32001");
        assert!(!summary.contains(secret));
        assert!(!summary.contains('\u{1b}'));

        let injected_static = "private\u{1b}[31m";
        for local_error in [
            McpError::InvalidLifecycleTransition {
                state: injected_static,
                event: injected_static,
            },
            McpError::InvalidLaunchConfiguration {
                field: injected_static,
                limit: 1,
            },
            McpError::InvalidToolSearch {
                field: injected_static,
                limit: 1,
            },
            McpError::CatalogContract {
                reason: injected_static,
            },
            McpError::InvalidEndpoint {
                field: injected_static,
                limit: 1,
            },
        ] {
            let summary = local_error.public_summary();
            assert!(!summary.contains(injected_static));
            assert!(!summary.contains('\u{1b}'));
        }
    }

    #[test]
    fn public_protocol_mismatch_summary_only_reflects_known_dated_versions() {
        let actionable = McpError::UnsupportedProtocolVersion {
            client_version: "2024-11-05".into(),
            server_version: "2099-01-01".into(),
        }
        .public_summary();
        assert!(actionable.contains("2024-11-05"));
        assert!(actionable.contains("2099-01-01"));

        let credential_shaped = ["gh", "p_", "AbCdEf1234567890AbCdEf1234567890"].concat();
        for unsafe_version in [
            credential_shaped,
            "2099-01-01\nforged".to_owned(),
            "2".repeat(65),
        ] {
            let redacted = McpError::UnsupportedProtocolVersion {
                client_version: "2024-11-05".into(),
                server_version: unsafe_version.clone(),
            }
            .public_summary();
            assert_eq!(
                redacted,
                "MCP server selected an unsupported protocol version"
            );
            assert!(!redacted.contains(&unsafe_version));
        }
    }

    #[test]
    fn tool_description_injection_is_detected() {
        assert!(suspicious_unicode("normal tool").is_none());
        assert!(suspicious_unicode("evil \u{202E}rev tool").is_some());
    }
}
