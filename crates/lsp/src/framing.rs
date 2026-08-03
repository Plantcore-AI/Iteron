//! LSP base protocol framing: `Content-Length: N\r\n\r\n` followed by exactly N bytes.
//!
//! This is deliberately not the newline-delimited transport the tool-server client uses. A
//! language server sends payloads containing raw newlines inside JSON strings, so length-prefixing
//! is the only correct framing, and the length must be honoured exactly -- reading "until it
//! parses" would resynchronise onto attacker-chosen boundaries after any malformed message.

use crate::{
    DEFAULT_BODY_READ_TIMEOUT_MS, DEFAULT_HEADER_READ_TIMEOUT_MS, LspError, MAX_CONTENT_BYTES,
    MAX_HEADER_BYTES, MAX_READ_TIMEOUT_MS, MIN_READ_TIMEOUT_MS,
};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

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

/// Parse a header block that has already been split off the stream.
///
/// Only `Content-Length` is load-bearing. `Content-Type` is accepted and ignored, and unknown
/// headers are ignored rather than rejected, because the spec permits them and a strict parser
/// here would break against servers that add their own.
pub fn parse_headers(block: &str) -> Result<usize, LspError> {
    if block.len() > MAX_HEADER_BYTES {
        return Err(LspError::HeaderTooLarge {
            limit: MAX_HEADER_BYTES,
        });
    }
    let mut content_length = None;
    for line in block.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| LspError::Header(format!("no colon in {line:?}")))?;
        if name.eq_ignore_ascii_case("content-length") {
            let parsed: usize = value
                .trim()
                .parse()
                .map_err(|_| LspError::Header(format!("Content-Length {:?}", value.trim())))?;
            // A second, different Content-Length is request smuggling, not sloppiness: two readers
            // could disagree on where the next message starts. Refuse rather than pick one.
            if content_length.is_some_and(|first| first != parsed) {
                return Err(LspError::Header("conflicting Content-Length".into()));
            }
            content_length = Some(parsed);
        }
    }
    content_length.ok_or(LspError::MissingContentLength)
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
    let value = serde_json::from_str(text).map_err(|e| LspError::Json(e.to_string()))?;
    Ok(Some(value))
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

    #[test]
    fn headers_are_case_insensitive_and_ignore_unknowns() {
        let block =
            "content-length: 42\r\nContent-Type: application/vscode-jsonrpc\r\nX-Odd: 1\r\n";
        assert_eq!(parse_headers(block).unwrap(), 42);
    }

    #[test]
    fn conflicting_content_length_is_refused() {
        let block = "Content-Length: 10\r\nContent-Length: 20\r\n";
        assert_eq!(
            parse_headers(block),
            Err(LspError::Header("conflicting Content-Length".into()))
        );
    }

    #[test]
    fn repeated_identical_content_length_is_accepted() {
        assert_eq!(
            parse_headers("Content-Length: 10\r\nContent-Length: 10\r\n").unwrap(),
            10
        );
    }

    #[test]
    fn missing_content_length_is_typed() {
        assert_eq!(
            parse_headers("Content-Type: x\r\n"),
            Err(LspError::MissingContentLength)
        );
    }

    #[tokio::test]
    async fn reads_a_body_containing_newlines_verbatim() {
        // The payload holds a literal newline inside a JSON string. Newline-delimited framing
        // would split this message in half; length-prefixed framing must not.
        let body = "{\"text\":\"a\\nb\"}";
        let mut r = cursor(&encode(body).unwrap());
        let value = read_message(&mut r).await.unwrap().unwrap();
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
    async fn invalid_utf8_body_is_typed_not_lossy() {
        let mut bytes = b"Content-Length: 4\r\n\r\n".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]);
        let mut r = cursor(&bytes);
        assert_eq!(read_message(&mut r).await, Err(LspError::InvalidUtf8));
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
