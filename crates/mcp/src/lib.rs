//! core-mcp — a Model Context Protocol client (stdio transport).
//!
//! MCP is the standard tool-ecosystem protocol, and Principal.md embraces the ecosystem at
//! standard protocol layers. This client spawns an MCP server, does the `initialize` handshake,
//! discovers tools (`tools/list`), and calls them (`tools/call`) over newline-delimited
//! JSON-RPC 2.0 on the server's stdin/stdout.
//!
//! SECURITY (ADR-007 R16): MCP-declared purity is UNTRUSTED. An MCP tool defaults to `Effecting`
//! (gated at message_stop + approval), never early-dispatched, until its confinement is
//! evidenced — a third-party server does not get to declare itself pure. Tool descriptions are
//! untrusted content and are scanned for bidi/invisible Unicode before the model sees them.
//!
//! What is here: the JSON-RPC framing (pure, unit-tested), the async stdio client, and the
//! mapping from an MCP tool to a `ToolSpec` with the untrusted defaults. Live testing needs a
//! real MCP server; the protocol layer is tested in isolation.

use serde_json::{Value, json};
use std::io::Write;

pub mod client;

pub use client::{McpClient, McpToolOutcome};

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

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("spawn: {0}")]
    Spawn(String),
    #[error("io: {0}")]
    Io(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("MCP frame exceeds {limit} byte limit")]
    FrameTooLarge { limit: usize },
    #[error("MCP response frames exceed {limit} aggregate byte limit")]
    ResponseTooLarge { limit: usize },
    #[error("MCP response exceeds {limit} frame limit")]
    TooManyFrames { limit: usize },
    #[error("MCP tool output exceeds {limit} byte limit")]
    OutputTooLarge { limit: usize },
    #[error("MCP frame is not valid UTF-8")]
    InvalidUtf8,
    #[error("deadline exceeded during {operation}")]
    Deadline { operation: String },
    #[error("server error {code}: {message}")]
    Server { code: i64, message: String },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
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
    fn tool_description_injection_is_detected() {
        assert!(suspicious_unicode("normal tool").is_none());
        assert!(suspicious_unicode("evil \u{202E}rev tool").is_some());
    }
}
