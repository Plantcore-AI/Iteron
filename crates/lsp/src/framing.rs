//! LSP base protocol framing: `Content-Length: N\r\n\r\n` followed by exactly N bytes.
//!
//! This is deliberately not the newline-delimited transport the tool-server client uses. JSON
//! strings encode a newline as the two wire bytes `\n` (a raw newline inside a JSON string is
//! illegal), while a JSON text may contain raw formatting newlines between tokens. The protocol's
//! length prefix is therefore the only authoritative message boundary, and it must be honoured
//! exactly -- reading "until it parses" could resynchronise onto attacker-chosen boundaries after
//! any malformed message.

use crate::{
    DEFAULT_BODY_READ_TIMEOUT_MS, DEFAULT_HEADER_READ_TIMEOUT_MS, LspError, MAX_CONTENT_BYTES,
    MAX_HEADER_BYTES, MAX_MESSAGE_JSON_ARRAY_ITEMS, MAX_MESSAGE_JSON_DEPTH, MAX_MESSAGE_JSON_NODES,
    MAX_MESSAGE_JSON_OBJECT_MEMBERS, MAX_MESSAGE_JSON_STRING_BYTES, MAX_READ_TIMEOUT_MS,
    MIN_READ_TIMEOUT_MS,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{fmt, time::Duration};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

pub use crate::headers::parse_headers;

const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Per-frame deadlines. Construction rejects zero and effectively-unbounded values; callers may
/// select a tighter value inside the hard interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadTimeouts {
    header_ms: u64,
    body_ms: u64,
}

impl Default for ReadTimeouts {
    fn default() -> Self {
        Self {
            header_ms: DEFAULT_HEADER_READ_TIMEOUT_MS,
            body_ms: DEFAULT_BODY_READ_TIMEOUT_MS,
        }
    }
}

impl ReadTimeouts {
    pub fn new(header_ms: u64, body_ms: u64) -> Result<Self, LspError> {
        validate_timeout("header read", header_ms)?;
        validate_timeout("body read", body_ms)?;
        Ok(Self { header_ms, body_ms })
    }

    pub fn header_ms(self) -> u64 {
        self.header_ms
    }

    pub fn body_ms(self) -> u64 {
        self.body_ms
    }
}

fn validate_timeout(kind: &'static str, value_ms: u64) -> Result<(), LspError> {
    if !(MIN_READ_TIMEOUT_MS..=MAX_READ_TIMEOUT_MS).contains(&value_ms) {
        return Err(LspError::InvalidTimeout {
            kind,
            value_ms,
            min_ms: MIN_READ_TIMEOUT_MS,
            max_ms: MAX_READ_TIMEOUT_MS,
        });
    }
    Ok(())
}

/// Encode one message. The body is written verbatim; callers pass already-serialised JSON so the
/// byte count in the header and the bytes on the wire cannot disagree.
pub fn encode(body: &str) -> Result<Vec<u8>, LspError> {
    if body.len() > MAX_CONTENT_BYTES {
        return Err(LspError::ContentTooLarge {
            value: body.len(),
            limit: MAX_CONTENT_BYTES,
        });
    }
    let mut out = Vec::with_capacity(body.len() + 32);
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body.as_bytes());
    Ok(out)
}

/// Read one framed message body as a JSON value.
///
/// Returns `Ok(None)` only on a clean end of stream at a message boundary -- that is a server
/// exiting, which the lifecycle treats differently from a server dying mid-message.
pub async fn read_message<R>(reader: &mut R) -> Result<Option<serde_json::Value>, LspError>
where
    R: AsyncBufRead + AsyncReadExt + Unpin,
{
    read_message_with_timeouts(reader, ReadTimeouts::default()).await
}

/// Read one frame under explicit header and body deadlines.
///
/// A timeout is terminal for the transport. The timed future may already have consumed a prefix,
/// so retrying on the same byte stream would interpret attacker-controlled body bytes as a new
/// header. The caller must close the stream and drive the lifecycle through a crash/restart.
pub async fn read_message_with_timeouts<R>(
    reader: &mut R,
    timeouts: ReadTimeouts,
) -> Result<Option<serde_json::Value>, LspError>
where
    R: AsyncBufRead + AsyncReadExt + Unpin,
{
    let header_result = tokio::time::timeout(
        Duration::from_millis(timeouts.header_ms),
        read_header_block(reader),
    )
    .await
    .map_err(|_| LspError::ReadTimeout {
        phase: "header",
        limit_ms: timeouts.header_ms,
    })?;
    let Some(header_block) = header_result? else {
        return Ok(None);
    };
    let length = parse_headers(&header_block)?;
    if length > MAX_CONTENT_BYTES {
        return Err(LspError::ContentTooLarge {
            value: length,
            limit: MAX_CONTENT_BYTES,
        });
    }

    // Allocation is bounded by the check above, so `Content-Length` cannot be used to make us
    // reserve memory the peer never intends to fill.
    let mut body = vec![0u8; length];
    tokio::time::timeout(
        Duration::from_millis(timeouts.body_ms),
        reader.read_exact(&mut body),
    )
    .await
    .map_err(|_| LspError::ReadTimeout {
        phase: "body",
        limit_ms: timeouts.body_ms,
    })?
    .map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            LspError::TruncatedMessage
        } else {
            LspError::Io(error.to_string())
        }
    })?;

    let text = std::str::from_utf8(&body).map_err(|_| LspError::InvalidUtf8)?;
    inspect_json_envelope(text)?;
    let value = serde_json::from_str(text).map_err(|e| LspError::Json(e.to_string()))?;
    Ok(Some(value))
}

/// Validate syntax and cap the retained JSON tree before constructing a `Value` DOM.
///
/// `Content-Length` bounds wire bytes, but a compact array of primitives can allocate many times
/// its wire size as `Value` slots. This first pass retains no tree: it only counts decoded strings,
/// nodes, object members, array items, and nesting depth with a streaming Serde visitor.
fn inspect_json_envelope(text: &str) -> Result<(), LspError> {
    let mut envelope = JsonEnvelope::default();
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let result = EnvelopeSeed {
        envelope: &mut envelope,
        depth: 0,
        slot: Slot::Root,
    }
    .deserialize(&mut deserializer);
    if let Some(error) = envelope.error.take() {
        return Err(error);
    }
    result.map_err(|error| LspError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| LspError::Json(error.to_string()))
}

#[derive(Debug, Clone, Copy)]
enum Slot {
    Root,
    ArrayItem,
    ObjectValue,
}

#[derive(Debug, Default)]
struct JsonEnvelope {
    nodes: usize,
    string_bytes: usize,
    object_members: usize,
    array_items: usize,
    error: Option<LspError>,
}

impl JsonEnvelope {
    fn enter<E>(&mut self, depth: usize, slot: Slot) -> Result<(), E>
    where
        E: de::Error,
    {
        if depth > MAX_MESSAGE_JSON_DEPTH {
            return self.reject::<E>("depth", depth, MAX_MESSAGE_JSON_DEPTH);
        }
        if matches!(slot, Slot::ArrayItem) {
            self.array_items = self.array_items.saturating_add(1);
            if self.array_items > MAX_MESSAGE_JSON_ARRAY_ITEMS {
                return self.reject::<E>(
                    "array items",
                    self.array_items,
                    MAX_MESSAGE_JSON_ARRAY_ITEMS,
                );
            }
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_MESSAGE_JSON_NODES {
            return self.reject::<E>("nodes", self.nodes, MAX_MESSAGE_JSON_NODES);
        }
        Ok(())
    }

    fn member<E>(&mut self) -> Result<(), E>
    where
        E: de::Error,
    {
        self.object_members = self.object_members.saturating_add(1);
        if self.object_members > MAX_MESSAGE_JSON_OBJECT_MEMBERS {
            return self.reject::<E>(
                "object members",
                self.object_members,
                MAX_MESSAGE_JSON_OBJECT_MEMBERS,
            );
        }
        Ok(())
    }

    fn string<E>(&mut self, bytes: usize) -> Result<(), E>
    where
        E: de::Error,
    {
        self.string_bytes = self.string_bytes.saturating_add(bytes);
        if self.string_bytes > MAX_MESSAGE_JSON_STRING_BYTES {
            return self.reject::<E>(
                "decoded string bytes",
                self.string_bytes,
                MAX_MESSAGE_JSON_STRING_BYTES,
            );
        }
        Ok(())
    }

    fn reject<E>(&mut self, dimension: &'static str, value: usize, limit: usize) -> Result<(), E>
    where
        E: de::Error,
    {
        self.error = Some(LspError::JsonEnvelopeExceeded {
            dimension,
            value,
            limit,
        });
        Err(E::custom("JSON resource envelope exceeded"))
    }
}

struct EnvelopeSeed<'a> {
    envelope: &'a mut JsonEnvelope,
    depth: usize,
    slot: Slot,
}

impl<'de> DeserializeSeed<'de> for EnvelopeSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.envelope.enter::<D::Error>(self.depth, self.slot)?;
        deserializer.deserialize_any(EnvelopeVisitor {
            envelope: self.envelope,
            depth: self.depth,
        })
    }
}

struct EnvelopeVisitor<'a> {
    envelope: &'a mut JsonEnvelope,
    depth: usize,
}

impl<'de> Visitor<'de> for EnvelopeVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value within the resource envelope")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> Result<(), E>
    where
        E: de::Error,
    {
        self.envelope.string::<E>(value.len())
    }

    fn visit_string<E>(self, value: String) -> Result<(), E>
    where
        E: de::Error,
    {
        self.envelope.string::<E>(value.len())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(EnvelopeSeed {
                envelope: self.envelope,
                depth: self.depth.saturating_add(1),
                slot: Slot::ArrayItem,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while map
            .next_key_seed(KeySeed {
                envelope: self.envelope,
            })?
            .is_some()
        {
            map.next_value_seed(EnvelopeSeed {
                envelope: self.envelope,
                depth: self.depth.saturating_add(1),
                slot: Slot::ObjectValue,
            })?;
        }
        Ok(())
    }
}

struct KeySeed<'a> {
    envelope: &'a mut JsonEnvelope,
}

impl<'de> DeserializeSeed<'de> for KeySeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(KeyVisitor {
            envelope: self.envelope,
        })
    }
}

struct KeyVisitor<'a> {
    envelope: &'a mut JsonEnvelope,
}

impl Visitor<'_> for KeyVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON object key")
    }

    fn visit_str<E>(self, value: &str) -> Result<(), E>
    where
        E: de::Error,
    {
        self.envelope.member::<E>()?;
        self.envelope.string::<E>(value.len())
    }

    fn visit_string<E>(self, value: String) -> Result<(), E>
    where
        E: de::Error,
    {
        self.visit_str::<E>(&value)
    }
}

/// Accumulate bytes up to the blank line that ends the header block.
async fn read_header_block<R>(reader: &mut R) -> Result<Option<String>, LspError>
where
    R: AsyncBufRead + Unpin,
{
    // `read_line`/`read_until` allocate through the delimiter and therefore let a single
    // unterminated attacker-controlled line exceed the nominal header limit before it is checked.
    // Consume the buffered stream byte by byte instead; the retained prefix is at most the header
    // ceiling plus the three-byte partial terminator needed to decide whether the ceiling was hit.
    let mut block = Vec::with_capacity(256);
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| LspError::Io(e.to_string()))?;
        if available.is_empty() {
            return if block.is_empty() {
                Ok(None)
            } else {
                Err(LspError::TruncatedMessage)
            };
        }

        let mut consumed = 0usize;
        let mut complete = None;
        let mut too_large = false;
        for byte in available {
            block.push(*byte);
            consumed += 1;

            if block.ends_with(HEADER_TERMINATOR) {
                let header_len = block.len() - HEADER_TERMINATOR.len();
                if header_len > MAX_HEADER_BYTES {
                    too_large = true;
                } else {
                    block.truncate(header_len);
                    complete = Some(());
                }
                break;
            }

            // At most three retained bytes can still become the prefix of `\r\n\r\n`. Once the
            // prefix is longer than `limit + 3`, no future byte can put the delimiter in bounds.
            if block.len() > MAX_HEADER_BYTES + HEADER_TERMINATOR.len() - 1 {
                too_large = true;
                break;
            }
        }
        reader.consume(consumed);

        if too_large {
            return Err(LspError::HeaderTooLarge {
                limit: MAX_HEADER_BYTES,
            });
        }
        if complete.is_some() {
            if !block.is_ascii() {
                return Err(LspError::Header("header block was not ASCII".into()));
            }
            // ASCII is a UTF-8 subset, checked above.
            return Ok(Some(
                String::from_utf8(block).expect("ASCII header is UTF-8"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor(bytes: &[u8]) -> std::io::Cursor<Vec<u8>> {
        std::io::Cursor::new(bytes.to_vec())
    }

    #[test]
    fn encoded_length_counts_bytes_not_characters() {
        // Eight ASCII bytes plus two CJK characters at three bytes each: 14 bytes but only 10
        // `char`s. A char count here would under-declare the body and desynchronise the stream
        // for every message after the first non-ASCII one.
        let body = r#"{"m":"中文"}"#;
        assert_eq!(body.len(), 14);
        assert_eq!(body.chars().count(), 10);

        let text = String::from_utf8(encode(body).unwrap()).unwrap();
        assert!(text.starts_with("Content-Length: 14\r\n\r\n"), "{text}");
    }

    #[tokio::test]
    async fn decodes_an_escaped_newline_in_a_json_string() {
        // The wire JSON contains backslash+n, not a raw newline inside the string. The decoded
        // value contains the newline character.
        let body = "{\"text\":\"a\\nb\"}";
        assert!(!body.contains('\n'));
        let mut r = cursor(&encode(body).unwrap());
        let value = read_message(&mut r).await.unwrap().unwrap();
        assert_eq!(value["text"], "a\nb");
    }

    #[tokio::test]
    async fn reads_raw_formatting_newlines_between_json_tokens() {
        let body = "{\n  \"text\": \"a\\nb\"\n}";
        assert!(body.contains('\n'));
        let mut reader = cursor(&encode(body).unwrap());
        let value = read_message(&mut reader).await.unwrap().unwrap();
        assert_eq!(value["text"], "a\nb");
    }

    #[tokio::test]
    async fn reads_two_messages_back_to_back() {
        let mut bytes = encode(r#"{"id":1}"#).unwrap();
        bytes.extend_from_slice(&encode(r#"{"id":2}"#).unwrap());
        let mut r = cursor(&bytes);
        assert_eq!(read_message(&mut r).await.unwrap().unwrap()["id"], 1);
        assert_eq!(read_message(&mut r).await.unwrap().unwrap()["id"], 2);
        assert!(read_message(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn clean_eof_is_none_but_short_body_is_truncation() {
        let mut empty = cursor(b"");
        assert!(read_message(&mut empty).await.unwrap().is_none());

        // Header promises 50 bytes, stream carries 4.
        let mut short = cursor(b"Content-Length: 50\r\n\r\n{}\r\n");
        assert_eq!(
            read_message(&mut short).await,
            Err(LspError::TruncatedMessage)
        );
    }

    #[tokio::test]
    async fn oversized_content_length_is_refused_before_allocating() {
        let header = format!("Content-Length: {}\r\n\r\n", MAX_CONTENT_BYTES + 1);
        let mut r = cursor(header.as_bytes());
        assert_eq!(
            read_message(&mut r).await,
            Err(LspError::ContentTooLarge {
                value: MAX_CONTENT_BYTES + 1,
                limit: MAX_CONTENT_BYTES,
            })
        );
    }

    #[tokio::test]
    async fn unterminated_header_block_is_bounded() {
        // A peer that never sends the blank line must not grow our buffer without limit.
        let mut flood = Vec::new();
        while flood.len() <= MAX_HEADER_BYTES {
            flood.extend_from_slice(b"X-Pad: 0123456789\r\n");
        }
        let mut r = cursor(&flood);
        assert_eq!(
            read_message(&mut r).await,
            Err(LspError::HeaderTooLarge {
                limit: MAX_HEADER_BYTES
            })
        );
    }

    #[tokio::test]
    async fn one_oversized_header_line_stops_consuming_at_the_bound() {
        let mut flood = b"X-Pad: ".to_vec();
        flood.resize(MAX_HEADER_BYTES * 4, b'a');
        let mut reader = cursor(&flood);

        assert_eq!(
            read_message(&mut reader).await,
            Err(LspError::HeaderTooLarge {
                limit: MAX_HEADER_BYTES
            })
        );
        assert!(
            reader.position() as usize <= MAX_HEADER_BYTES + HEADER_TERMINATOR.len(),
            "the ceiling must bound bytes consumed, not only the eventual verdict"
        );
    }

    #[tokio::test]
    async fn invalid_utf8_body_is_typed_not_lossy() {
        let mut bytes = b"Content-Length: 4\r\n\r\n".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]);
        let mut r = cursor(&bytes);
        assert_eq!(read_message(&mut r).await, Err(LspError::InvalidUtf8));
    }

    #[tokio::test]
    async fn near_limit_wide_array_is_refused_before_dom_amplification() {
        let mut body = String::with_capacity(12 * 1024 * 1024);
        body.push('[');
        for index in 0..=MAX_MESSAGE_JSON_ARRAY_ITEMS {
            if index != 0 {
                body.push(',');
            }
            body.push('0');
            body.extend(std::iter::repeat_n(' ', 180));
        }
        body.push(']');
        assert!(body.len() > MAX_CONTENT_BYTES / 2);
        assert!(body.len() <= MAX_CONTENT_BYTES);

        let mut reader = cursor(&encode(&body).unwrap());
        assert_eq!(
            read_message(&mut reader).await,
            Err(LspError::JsonEnvelopeExceeded {
                dimension: "array items",
                value: MAX_MESSAGE_JSON_ARRAY_ITEMS + 1,
                limit: MAX_MESSAGE_JSON_ARRAY_ITEMS
            })
        );
    }

    #[tokio::test]
    async fn near_limit_wide_object_is_refused_before_dom_amplification() {
        use std::fmt::Write as _;

        let mut body = String::with_capacity(12 * 1024 * 1024);
        body.push('{');
        for index in 0..=MAX_MESSAGE_JSON_OBJECT_MEMBERS {
            if index != 0 {
                body.push(',');
            }
            write!(&mut body, "\"k{index}\":0").unwrap();
            body.extend(std::iter::repeat_n(' ', 170));
        }
        body.push('}');
        assert!(body.len() > MAX_CONTENT_BYTES / 2);
        assert!(body.len() <= MAX_CONTENT_BYTES);

        let mut reader = cursor(&encode(&body).unwrap());
        assert_eq!(
            read_message(&mut reader).await,
            Err(LspError::JsonEnvelopeExceeded {
                dimension: "object members",
                value: MAX_MESSAGE_JSON_OBJECT_MEMBERS + 1,
                limit: MAX_MESSAGE_JSON_OBJECT_MEMBERS
            })
        );
    }

    #[test]
    fn decoded_strings_nodes_and_depth_have_independent_pre_dom_envelopes() {
        let large = "x".repeat(MAX_MESSAGE_JSON_STRING_BYTES / 2 + 1);
        let strings = serde_json::to_string(&vec![large.clone(), large]).unwrap();
        assert!(matches!(
            inspect_json_envelope(&strings),
            Err(LspError::JsonEnvelopeExceeded {
                dimension: "decoded string bytes",
                ..
            })
        ));

        let item = r#"{"k":0}"#;
        let mixed = format!(
            "[{}]",
            std::iter::repeat_n(item, 50_000)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(matches!(
            inspect_json_envelope(&mixed),
            Err(LspError::JsonEnvelopeExceeded {
                dimension: "nodes",
                ..
            })
        ));

        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_MESSAGE_JSON_DEPTH + 1),
            "]".repeat(MAX_MESSAGE_JSON_DEPTH + 1)
        );
        assert!(matches!(
            inspect_json_envelope(&deep),
            Err(LspError::JsonEnvelopeExceeded {
                dimension: "depth",
                ..
            })
        ));
    }

    #[test]
    fn outbound_messages_are_bounded_too() {
        let body = "x".repeat(MAX_CONTENT_BYTES + 1);
        assert_eq!(
            encode(&body),
            Err(LspError::ContentTooLarge {
                value: MAX_CONTENT_BYTES + 1,
                limit: MAX_CONTENT_BYTES
            })
        );
    }

    #[test]
    fn timeout_configuration_cannot_disable_the_deadline() {
        assert!(matches!(
            ReadTimeouts::new(0, DEFAULT_BODY_READ_TIMEOUT_MS),
            Err(LspError::InvalidTimeout {
                kind: "header read",
                ..
            })
        ));
        assert!(matches!(
            ReadTimeouts::new(DEFAULT_HEADER_READ_TIMEOUT_MS, MAX_READ_TIMEOUT_MS + 1),
            Err(LspError::InvalidTimeout {
                kind: "body read",
                ..
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_header_hits_a_terminal_deadline() {
        let (_writer, reader) = tokio::io::duplex(64);
        let mut reader = tokio::io::BufReader::new(reader);
        let task = tokio::spawn(async move {
            read_message_with_timeouts(&mut reader, ReadTimeouts::new(10, 10).unwrap()).await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(11)).await;
        assert_eq!(
            task.await.unwrap(),
            Err(LspError::ReadTimeout {
                phase: "header",
                limit_ms: 10
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_body_has_a_separate_terminal_deadline() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, reader) = tokio::io::duplex(128);
        let mut reader = tokio::io::BufReader::new(reader);
        writer
            .write_all(b"Content-Length: 10\r\n\r\n{}")
            .await
            .unwrap();
        let task = tokio::spawn(async move {
            read_message_with_timeouts(&mut reader, ReadTimeouts::new(10, 20).unwrap()).await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(21)).await;
        assert_eq!(
            task.await.unwrap(),
            Err(LspError::ReadTimeout {
                phase: "body",
                limit_ms: 20
            })
        );
    }
}
