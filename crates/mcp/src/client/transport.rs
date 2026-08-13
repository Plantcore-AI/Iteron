//! Bounded newline-delimited JSON-RPC response transport.

use crate::{MAX_FRAME_BYTES, MAX_RESPONSE_BYTES, MAX_RESPONSE_FRAMES, McpError, parse_response};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

const READ_BUFFER_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy)]
pub(super) struct ResponseLimits {
    pub(super) frame_bytes: usize,
    pub(super) aggregate_bytes: usize,
    pub(super) frames: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            frame_bytes: MAX_FRAME_BYTES,
            aggregate_bytes: iteron_tunables::param_integer(
                "mcp.lib.max_response_bytes",
                MAX_RESPONSE_BYTES,
            ),
            frames: iteron_tunables::param_integer(
                "mcp.lib.max_response_frames",
                MAX_RESPONSE_FRAMES,
            ),
        }
    }
}

/// Read one newline-delimited frame with a hard allocation ceiling. Invalid UTF-8 is handled by
/// the response parser as a typed failure; this layer remains byte-oriented so a hostile peer
/// cannot force incremental `String` growth before validation.
pub(super) async fn read_frame<R>(reader: &mut R, limit: usize) -> Result<Option<Vec<u8>>, McpError>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::with_capacity(limit.min(iteron_tunables::param_integer(
        "mcp.client.transport.read_buffer_bytes",
        READ_BUFFER_BYTES,
    )));
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| McpError::Io(e.to_string()))?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(McpError::TransportClosed)
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

pub(super) async fn read_matching_response<R>(
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
            .ok_or(McpError::TransportClosed)?;
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
