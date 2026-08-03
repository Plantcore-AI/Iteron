//! LSP base protocol framing: `Content-Length: N\r\n\r\n` followed by exactly N bytes.
//!
//! This is deliberately not the newline-delimited transport the tool-server client uses. A
//! language server sends payloads containing raw newlines inside JSON strings, so length-prefixing
//! is the only correct framing, and the length must be honoured exactly -- reading "until it
//! parses" would resynchronise onto attacker-chosen boundaries after any malformed message.

use crate::{LspError, MAX_CONTENT_BYTES, MAX_HEADER_BYTES};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

/// Encode one message. The body is written verbatim; callers pass already-serialised JSON so the
/// byte count in the header and the bytes on the wire cannot disagree.
pub fn encode(body: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 32);
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

/// Parse a header block that has already been split off the stream.
///
/// Only `Content-Length` is load-bearing. `Content-Type` is accepted and ignored, and unknown
/// headers are ignored rather than rejected, because the spec permits them and a strict parser
/// here would break against servers that add their own.
pub fn parse_headers(block: &str) -> Result<usize, LspError> {
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
    let Some(header_block) = read_header_block(reader).await? else {
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
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| LspError::TruncatedMessage)?;

    let text = std::str::from_utf8(&body).map_err(|_| LspError::InvalidUtf8)?;
    let value = serde_json::from_str(text).map_err(|e| LspError::Json(e.to_string()))?;
    Ok(Some(value))
}

/// Accumulate bytes up to the blank line that ends the header block.
async fn read_header_block<R>(reader: &mut R) -> Result<Option<String>, LspError>
where
    R: AsyncBufRead + Unpin,
{
    let mut block = String::new();
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .await
            .map_err(|e| LspError::Io(e.to_string()))?;
        if read == 0 {
            return if block.is_empty() {
                Ok(None)
            } else {
                Err(LspError::TruncatedMessage)
            };
        }
        if line == "\r\n" || line == "\n" {
            return Ok(Some(block));
        }
        if block.len() + line.len() > MAX_HEADER_BYTES {
            return Err(LspError::HeaderTooLarge {
                limit: MAX_HEADER_BYTES,
            });
        }
        block.push_str(line.trim_end_matches('\n').trim_end_matches('\r'));
        block.push_str("\r\n");
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

        let text = String::from_utf8(encode(body)).unwrap();
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
        let mut r = cursor(&encode(body));
        let value = read_message(&mut r).await.unwrap().unwrap();
        assert_eq!(value["text"], "a\nb");
    }

    #[tokio::test]
    async fn reads_two_messages_back_to_back() {
        let mut bytes = encode(r#"{"id":1}"#);
        bytes.extend_from_slice(&encode(r#"{"id":2}"#));
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
}
