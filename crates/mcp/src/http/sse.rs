//! Framing: recovering JSON-RPC message boundaries from an HTTP response body.
//!
//! The stdio transport gets framing for free — one JSON-RPC message per line, and
//! `client::transport::read_frame` already bounds it. HTTP does not: the body is either one JSON
//! document or a `text/event-stream`, and the event stream has its own grammar layered under the
//! JSON-RPC one.
//!
//! Three things about that grammar are easy to get wrong and are handled here:
//!
//! **Line terminators.** The event-stream grammar has three — `\n`, `\r\n`, and a bare `\r`. The
//! stdio reader splits on `\n` and strips a trailing `\r`, which silently mis-frames a stream that
//! uses bare `\r`: the whole body becomes one line and nothing ever dispatches. [`SseLineReader`]
//! handles all three, including the case where `\r` and `\n` land in different reads.
//!
//! **Comments are the keepalive.** A `:`-prefixed line is how a server holds a connection open. It
//! must not dispatch an event and must not be mistaken for data — but it must still be *charged*
//! against a ceiling, or an infinite comment stream is an unbounded wait that no frame counter
//! ever notices.
//!
//! **An event with no `data` is discarded.** Per the grammar, a blank line with an empty data
//! buffer dispatches nothing at all, and the accumulated `event:` name is dropped with it. Treating
//! it as an empty message would hand `serde_json` an empty string on every keepalive boundary.
//!
//! The ceilings are the stdio ceilings, deliberately: one JSON-RPC message must not be larger over
//! HTTP than over a pipe, or the two transports have different memory contracts for the same
//! protocol.

use crate::{
    MAX_FRAME_BYTES, MAX_RESPONSE_BYTES, MAX_RESPONSE_FRAMES, McpError, McpFuture, parse_response,
};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

const READ_BUFFER_BYTES: usize = 8 * 1024;

/// Ceilings for one response body. Same numbers as the stdio transport's [`crate::MAX_FRAME_BYTES`]
/// family, so a message that a pipe would refuse is refused over HTTP too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseLimits {
    /// Maximum bytes in one dispatched event's assembled `data`.
    pub event_bytes: usize,
    /// Maximum bytes read from the body in total, including comments and discarded events.
    pub aggregate_bytes: usize,
    /// Maximum number of dispatched events inspected while waiting for one correlated response.
    pub events: usize,
}

impl Default for SseLimits {
    fn default() -> Self {
        Self {
            event_bytes: MAX_FRAME_BYTES,
            aggregate_bytes: MAX_RESPONSE_BYTES,
            events: MAX_RESPONSE_FRAMES,
        }
    }
}

/// One dispatched event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    /// Absent means the default event type, which is what MCP messages use.
    pub event: Option<String>,
    pub data: String,
    /// Retained but unused: resumability (`Last-Event-ID`) needs a server-side redelivery contract
    /// that does not exist yet. Keeping the field means the decoder does not change when it lands.
    pub id: Option<String>,
    pub retry_ms: Option<u64>,
}

#[derive(Default)]
struct Pending {
    event: Option<String>,
    data: String,
    /// Whether any `data` field was seen, which is *not* the same as `!data.is_empty()`.
    ///
    /// The grammar appends a newline after every `data` value and strips one at dispatch, so a
    /// lone `data:` leaves a non-empty buffer that renders as the empty string, and a `data:` with
    /// an empty value followed by `data: x` renders as `"\nx"`. Deciding either question from
    /// `data.is_empty()` gets both cases wrong: it swallows the leading blank line and it silently
    /// drops an event the peer did send.
    has_data: bool,
    id: Option<String>,
    retry_ms: Option<u64>,
}

/// The pure half of the framing: bytes are already split into lines, and this decides what they
/// mean. Everything testable about the grammar is testable here, without a socket.
pub struct SseDecoder {
    limits: SseLimits,
    pending: Pending,
    bytes_seen: usize,
    events_dispatched: usize,
    at_stream_start: bool,
}

impl SseDecoder {
    pub fn new(limits: SseLimits) -> Self {
        Self {
            limits,
            pending: Pending::default(),
            bytes_seen: 0,
            events_dispatched: 0,
            at_stream_start: true,
        }
    }

    /// Feed one line with its terminator already removed. Returns an event only at a blank line
    /// that closes a non-empty data buffer.
    pub fn push_line(&mut self, line: &str) -> Result<Option<SseEvent>, McpError> {
        // Charge the terminator too: otherwise a flood of empty lines is free forever.
        self.bytes_seen = self
            .bytes_seen
            .checked_add(line.len().saturating_add(1))
            .ok_or(McpError::ResponseTooLarge {
                limit: self.limits.aggregate_bytes,
            })?;
        if self.bytes_seen > self.limits.aggregate_bytes {
            return Err(McpError::ResponseTooLarge {
                limit: self.limits.aggregate_bytes,
            });
        }

        let line = if std::mem::take(&mut self.at_stream_start) {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };

        if line.is_empty() {
            return self.dispatch();
        }
        if line.starts_with(':') {
            // Keepalive comment: charged above, dispatches nothing.
            return Ok(None);
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "event" => self.pending.event = Some(value.to_owned()),
            "data" => {
                let separator = usize::from(self.pending.has_data);
                if self.pending.data.len() + value.len() + separator > self.limits.event_bytes {
                    return Err(McpError::FrameTooLarge {
                        limit: self.limits.event_bytes,
                    });
                }
                if self.pending.has_data {
                    self.pending.data.push('\n');
                }
                self.pending.data.push_str(value);
                self.pending.has_data = true;
            }
            // A NUL in the id is refused by the grammar; taking it would put an unusable value
            // into a header on any future resumption attempt.
            "id" if !value.contains('\0') => self.pending.id = Some(value.to_owned()),
            "retry" if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
                self.pending.retry_ms = value.parse::<u64>().ok();
            }
            // Unknown fields, and malformed `id`/`retry`, are ignored by the grammar.
            _ => {}
        }
        Ok(None)
    }

    fn dispatch(&mut self) -> Result<Option<SseEvent>, McpError> {
        let pending = std::mem::take(&mut self.pending);
        if !pending.has_data {
            // No data field at all means no event, and the accumulated name is dropped with it.
            return Ok(None);
        }
        self.events_dispatched += 1;
        if self.events_dispatched > self.limits.events {
            return Err(McpError::TooManyFrames {
                limit: self.limits.events,
            });
        }
        Ok(Some(SseEvent {
            event: pending.event,
            data: pending.data,
            id: pending.id,
            retry_ms: pending.retry_ms,
        }))
    }
}

/// Splits a body into event-stream lines across all three terminators.
///
/// The `\r`/`\n` pair may straddle two reads, so "saw a CR, swallow one LF if it turns up next" is
/// state on the reader rather than a lookahead in one buffer. Without it a `\r\n` stream produces a
/// spurious blank line after every real line — which, in this grammar, dispatches an event early.
pub struct SseLineReader<R> {
    reader: R,
    swallow_leading_lf: bool,
}

impl<R: AsyncBufRead + Unpin> SseLineReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            swallow_leading_lf: false,
        }
    }

    /// The next line without its terminator, or `None` at end of stream.
    ///
    /// A final unterminated line is discarded: the grammar dispatches on a blank line, so a
    /// truncated stream must not be able to complete a message that the server never finished.
    pub async fn next_line(&mut self, limit: usize) -> Result<Option<Vec<u8>>, McpError> {
        let mut line: Vec<u8> = Vec::new();
        loop {
            let available = self
                .reader
                .fill_buf()
                .await
                .map_err(|error| McpError::Io(error.to_string()))?;
            if available.is_empty() {
                return Ok(None);
            }
            if self.swallow_leading_lf {
                let consume = usize::from(available[0] == b'\n');
                self.reader.consume(consume);
                self.swallow_leading_lf = false;
                continue;
            }
            if let Some(position) = available
                .iter()
                .position(|byte| *byte == b'\n' || *byte == b'\r')
            {
                if position > limit.saturating_sub(line.len()) {
                    return Err(McpError::FrameTooLarge { limit });
                }
                line.extend_from_slice(&available[..position]);
                let terminator = available[position];
                self.reader.consume(position + 1);
                self.swallow_leading_lf = terminator == b'\r';
                return Ok(Some(line));
            }
            if available.len() > limit.saturating_sub(line.len()) {
                return Err(McpError::FrameTooLarge { limit });
            }
            let consumed = available.len();
            line.extend_from_slice(available);
            self.reader.consume(consumed);
        }
    }
}

/// Read an event stream until the JSON-RPC message with `id` arrives.
///
/// Interleaved server notifications and events of other types are skipped, exactly as the stdio
/// reader skips non-matching frames on the shared pipe.
pub async fn read_matching_sse_response<R>(
    reader: R,
    id: u64,
    limits: SseLimits,
) -> Result<Value, McpError>
where
    R: AsyncBufRead + Unpin,
{
    read_matching_sse_response_with(reader, id, limits, &IgnoreInbound).await
}

/// Inbound server request/notification sink used while a correlated response is still pending.
/// This is crate-private because the public extension point is the narrower, typed
/// [`crate::McpElicitationHandler`].
pub(crate) trait SseInbound: Send + Sync {
    fn handle<'a>(&'a self, message: Value) -> McpFuture<'a, ()>;
}

struct IgnoreInbound;

impl SseInbound for IgnoreInbound {
    fn handle<'a>(&'a self, _message: Value) -> McpFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

pub(crate) async fn read_matching_sse_response_with<R, H>(
    reader: R,
    id: u64,
    limits: SseLimits,
    inbound: &H,
) -> Result<Value, McpError>
where
    R: AsyncBufRead + Unpin,
    H: SseInbound + ?Sized,
{
    let mut lines = SseLineReader::new(reader);
    let mut decoder = SseDecoder::new(limits);
    while let Some(raw) = lines.next_line(limits.event_bytes).await? {
        let text = std::str::from_utf8(&raw).map_err(|_| McpError::InvalidUtf8)?;
        let Some(event) = decoder.push_line(text)? else {
            continue;
        };
        // MCP carries JSON-RPC on the default event type; a server may emit others for its own
        // purposes and they are not protocol errors.
        if event.event.as_deref().is_some_and(|name| name != "message") {
            continue;
        }
        // The grammar dispatches a lone `data:` as an event whose payload is the empty string.
        // That is not a JSON-RPC message and not a protocol violation either — feeding it to the
        // parser would turn a harmless server quirk into a failed tool call.
        if event.data.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&event.data)?;
        if value.get("method").and_then(Value::as_str).is_some() {
            inbound.handle(value).await?;
        } else if value.get("id").and_then(Value::as_u64) == Some(id) {
            return parse_response(&event.data);
        }
    }
    Err(McpError::TransportClosed)
}

/// Read a single-document `application/json` body and correlate it.
pub async fn read_json_response<R>(reader: &mut R, id: u64, limit: usize) -> Result<Value, McpError>
where
    R: AsyncBufRead + Unpin,
{
    let mut body: Vec<u8> = Vec::with_capacity(limit.min(READ_BUFFER_BYTES));
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| McpError::Io(error.to_string()))?;
        if available.is_empty() {
            break;
        }
        if available.len() > limit.saturating_sub(body.len()) {
            return Err(McpError::FrameTooLarge { limit });
        }
        let consumed = available.len();
        body.extend_from_slice(available);
        reader.consume(consumed);
    }
    let text = std::str::from_utf8(&body).map_err(|_| McpError::InvalidUtf8)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(McpError::TransportClosed);
    }
    let value: Value = serde_json::from_str(trimmed)?;
    if value.get("id").and_then(Value::as_u64) != Some(id) {
        // A single-document response has exactly one message in it, so a mismatched id is not
        // something to skip past — it is the wrong answer to this request.
        return Err(McpError::Protocol("uncorrelated JSON response".into()));
    }
    parse_response(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader, duplex};

    fn decode_all(body: &str, limits: SseLimits) -> Result<Vec<SseEvent>, McpError> {
        let mut decoder = SseDecoder::new(limits);
        let mut events = Vec::new();
        for line in split_lines(body) {
            if let Some(event) = decoder.push_line(&line)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    /// The pure-side mirror of [`SseLineReader`], so grammar tests do not need a socket.
    fn split_lines(body: &str) -> Vec<String> {
        let mut lines = Vec::new();
        let mut current = String::new();
        let mut bytes = body.chars().peekable();
        while let Some(character) = bytes.next() {
            match character {
                '\n' => lines.push(std::mem::take(&mut current)),
                '\r' => {
                    if bytes.peek() == Some(&'\n') {
                        bytes.next();
                    }
                    lines.push(std::mem::take(&mut current));
                }
                other => current.push(other),
            }
        }
        lines
    }

    async fn reader_for(body: &'static str) -> BufReader<tokio::io::DuplexStream> {
        let (mut peer, stream) = duplex(body.len().max(1));
        tokio::spawn(async move {
            let _ = peer.write_all(body.as_bytes()).await;
        });
        BufReader::new(stream)
    }

    #[test]
    fn multi_line_data_joins_with_newlines_and_the_event_name_defaults() {
        let events = decode_all(
            "event: message\ndata: {\"a\":1,\ndata: \"b\":2}\n\ndata: bare\n\n",
            SseLimits::default(),
        )
        .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event.as_deref(), Some("message"));
        assert_eq!(events[0].data, "{\"a\":1,\n\"b\":2}");
        assert_eq!(events[1].event, None);
        assert_eq!(events[1].data, "bare");
    }

    #[test]
    fn a_keepalive_comment_dispatches_nothing_but_is_still_charged() {
        // The failure this prevents: a server holds the connection open with `: ping` forever. No
        // event is ever dispatched, so an event counter never fires, and the read never returns.
        let events = decode_all(": ping\n: ping\ndata: x\n\n", SseLimits::default()).unwrap();
        assert_eq!(events.len(), 1);

        let limits = SseLimits {
            aggregate_bytes: 24,
            ..SseLimits::default()
        };
        let error = decode_all(&": ping\n".repeat(64), limits).unwrap_err();
        assert!(matches!(error, McpError::ResponseTooLarge { limit: 24 }));
    }

    #[test]
    fn a_blank_line_with_no_data_dispatches_nothing_and_drops_the_pending_name() {
        // Treating this as an empty message would hand serde_json "" at every keepalive boundary.
        let events = decode_all("event: message\n\ndata: real\n\n", SseLimits::default()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "real");
        assert_eq!(
            events[0].event, None,
            "the discarded event's name must not leak into the next one"
        );
    }

    #[test]
    fn field_syntax_follows_the_grammar_including_its_odd_corners() {
        // One leading space after the colon is part of the syntax, not the value; a second is data.
        let events = decode_all("data:  padded\n\n", SseLimits::default()).unwrap();
        assert_eq!(events[0].data, " padded");
        // A line with no colon is a field with an empty value. The grammar appends a newline after
        // every `data` value and strips one at dispatch, so an empty first value is a leading blank
        // line in the payload — deciding this from `data.is_empty()` silently swallows it.
        let events = decode_all("data\ndata: x\n\n", SseLimits::default()).unwrap();
        assert_eq!(events[0].data, "\nx");
        let events = decode_all("data:\ndata:\n\n", SseLimits::default()).unwrap();
        assert_eq!(events[0].data, "\n");
        // Unknown fields and malformed retry/id values are ignored, not errors.
        let events = decode_all(
            "unknown: v\nretry: soon\nid: has\0nul\ndata: x\n\n",
            SseLimits::default(),
        )
        .unwrap();
        assert_eq!(events[0].retry_ms, None);
        assert_eq!(events[0].id, None);
        let events = decode_all("retry: 2500\nid: e-7\ndata: x\n\n", SseLimits::default()).unwrap();
        assert_eq!(events[0].retry_ms, Some(2_500));
        assert_eq!(events[0].id.as_deref(), Some("e-7"));
    }

    #[test]
    fn a_leading_byte_order_mark_belongs_to_the_stream_not_to_the_first_field() {
        // Without stripping it the first field name is "\u{feff}data", which is silently ignored,
        // so the first message of the stream vanishes and nothing reports why.
        let events = decode_all("\u{feff}data: first\n\n", SseLimits::default()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "first");
    }

    #[test]
    fn one_message_is_no_larger_over_http_than_over_a_pipe() {
        let limits = SseLimits {
            event_bytes: 16,
            ..SseLimits::default()
        };
        let error = decode_all("data: 0123456789abcdefg\n\n", limits).unwrap_err();
        assert!(matches!(error, McpError::FrameTooLarge { limit: 16 }));

        let limits = SseLimits {
            events: 2,
            ..SseLimits::default()
        };
        let error = decode_all("data: a\n\ndata: b\n\ndata: c\n\n", limits).unwrap_err();
        assert!(matches!(error, McpError::TooManyFrames { limit: 2 }));
    }

    #[tokio::test]
    async fn all_three_line_terminators_frame_identically() {
        // A bare `\r` stream is the one the stdio reader would mis-frame into a single line that
        // never dispatches.
        for body in [
            "data: a\n\ndata: b\n\n",
            "data: a\r\n\r\ndata: b\r\n\r\n",
            "data: a\r\rdata: b\r\r",
        ] {
            let (mut peer, stream) = duplex(body.len());
            let written = body.to_owned();
            tokio::spawn(async move {
                let _ = peer.write_all(written.as_bytes()).await;
            });
            let mut lines = SseLineReader::new(BufReader::new(stream));
            let mut decoder = SseDecoder::new(SseLimits::default());
            let mut events = Vec::new();
            while let Some(raw) = lines.next_line(1024).await.unwrap() {
                if let Some(event) = decoder
                    .push_line(std::str::from_utf8(&raw).unwrap())
                    .unwrap()
                {
                    events.push(event.data);
                }
            }
            assert_eq!(events, ["a", "b"], "terminator handling for {body:?}");
        }
    }

    #[tokio::test]
    async fn a_crlf_split_across_two_reads_does_not_become_a_spurious_blank_line() {
        // The `\r` and the `\n` land in different `fill_buf` results. A lookahead inside one
        // buffer misses this and dispatches the pending event one line early.
        let (mut peer, stream) = duplex(4);
        tokio::spawn(async move {
            for chunk in ["data: a\r", "\n\r", "\ndata: b\r", "\n\r", "\n"] {
                let _ = peer.write_all(chunk.as_bytes()).await;
            }
        });
        let mut lines = SseLineReader::new(BufReader::with_capacity(2, stream));
        let mut decoder = SseDecoder::new(SseLimits::default());
        let mut events = Vec::new();
        while let Some(raw) = lines.next_line(1024).await.unwrap() {
            if let Some(event) = decoder
                .push_line(std::str::from_utf8(&raw).unwrap())
                .unwrap()
            {
                events.push(event.data);
            }
        }
        assert_eq!(events, ["a", "b"]);
    }

    #[tokio::test]
    async fn a_correlated_response_is_found_past_interleaved_notifications() {
        let body = concat!(
            ": keepalive\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n",
            "event: telemetry\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"wrong\":true}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"stale\":true}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[]}}\n\n",
        );
        let result = read_matching_sse_response(reader_for(body).await, 7, SseLimits::default())
            .await
            .unwrap();
        assert!(result.get("tools").is_some());
        assert!(
            result.get("wrong").is_none(),
            "a non-default event type is not a JSON-RPC message"
        );
    }

    #[tokio::test]
    async fn an_empty_payload_event_is_skipped_rather_than_handed_to_the_json_parser() {
        // `data:` with no value dispatches, by the grammar, an event whose payload is "". It is
        // not a JSON-RPC message and not a protocol violation; parsing it would turn a harmless
        // server quirk into a failed tool call.
        let body = concat!(
            "data:\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":true}}\n\n",
        );
        let result = read_matching_sse_response(reader_for(body).await, 2, SseLimits::default())
            .await
            .unwrap();
        assert_eq!(result["ok"], true);
    }

    #[tokio::test]
    async fn a_stream_that_ends_without_the_response_is_a_closed_transport() {
        let body = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        let error = read_matching_sse_response(reader_for(body).await, 9, SseLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::TransportClosed));

        // A truncated final event must not dispatch: the blank line never arrived.
        let truncated = "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}";
        let error =
            read_matching_sse_response(reader_for(truncated).await, 9, SseLimits::default())
                .await
                .unwrap_err();
        assert!(matches!(error, McpError::TransportClosed));
    }

    #[tokio::test]
    async fn a_server_error_over_sse_stays_an_authoritative_server_error() {
        let body = concat!(
            "data: {\"jsonrpc\":\"2.0\",\"id\":3,",
            "\"error\":{\"code\":-32601,\"message\":\"method not found\"}}\n\n",
        );
        let error = read_matching_sse_response(reader_for(body).await, 3, SseLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::Server { code: -32601, .. }));
    }

    #[tokio::test]
    async fn a_single_document_body_must_answer_the_request_it_was_sent_for() {
        let mut reader =
            reader_for("{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"ok\":true}}").await;
        let result = read_json_response(&mut reader, 4, MAX_FRAME_BYTES)
            .await
            .unwrap();
        assert_eq!(result["ok"], true);

        let mut reader = reader_for("{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{}}").await;
        let error = read_json_response(&mut reader, 4, MAX_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::Protocol(_)));

        let mut reader = reader_for("").await;
        let error = read_json_response(&mut reader, 4, MAX_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::TransportClosed));
    }

    #[tokio::test]
    async fn an_unbounded_json_body_is_refused_before_it_is_collected() {
        let (mut peer, stream) = duplex(64);
        tokio::spawn(async move {
            for _ in 0..64 {
                if peer.write_all(&[b'x'; 64]).await.is_err() {
                    return;
                }
            }
        });
        let mut reader = BufReader::with_capacity(32, stream);
        let error = read_json_response(&mut reader, 1, 128).await.unwrap_err();
        assert!(matches!(error, McpError::FrameTooLarge { limit: 128 }));
    }

    #[tokio::test]
    async fn invalid_utf8_in_a_body_is_a_typed_failure_in_both_shapes() {
        let (mut peer, stream) = duplex(8);
        peer.write_all(&[0xff, b'\n']).await.unwrap();
        drop(peer);
        let error = read_matching_sse_response(BufReader::new(stream), 1, SseLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::InvalidUtf8));

        let (mut peer, stream) = duplex(8);
        peer.write_all(&[0xff]).await.unwrap();
        drop(peer);
        let mut reader = BufReader::new(stream);
        let error = read_json_response(&mut reader, 1, 128).await.unwrap_err();
        assert!(matches!(error, McpError::InvalidUtf8));
    }
}
