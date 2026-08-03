//! LSP base protocol framing: `Content-Length: N\r\n\r\n` followed by exactly N bytes.
//!
//! This is deliberately not the newline-delimited transport the tool-server client uses. A
//! language server sends payloads containing raw newlines inside JSON strings, so length-prefixing
//! is the only correct framing, and the length must be honoured exactly -- reading "until it
//! parses" would resynchronise onto attacker-chosen boundaries after any malformed message.

use crate::{LspError, MAX_CONTENT_BYTES, MAX_HEADER_BYTES, MAX_JSON_DEPTH};
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
    // Depth is checked before the DOM is built, not after. `[[[[...]]]]` inside an otherwise legal
    // frame costs a couple of bytes per level on the wire and a full `Value` node with its own
    // allocation per level in memory, so a body that passes the byte ceiling can still amplify well
    // past it. Scanning the text first is O(n) with no allocation, which is exactly what a check
    // guarding against allocation should be.
    check_depth(text)?;
    let value = serde_json::from_str(text).map_err(|e| LspError::Json(e.to_string()))?;
    Ok(Some(value))
}

/// Reject a body nested deeper than [`MAX_JSON_DEPTH`] before it is turned into a DOM.
///
/// Quote-aware, because a `[` inside a string literal is text, not structure -- counting it would
/// reject legitimate payloads full of code snippets, which is most of what a language server sends.
fn check_depth(text: &str) -> Result<(), LspError> {
    let (mut depth, mut max) = (0usize, 0usize);
    let (mut in_string, mut escaped) = (false, false);
    for b in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
                if max > MAX_JSON_DEPTH {
                    return Err(LspError::TooDeep {
                        limit: MAX_JSON_DEPTH,
                    });
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// Accumulate bytes up to the blank line that ends the header block.
async fn read_header_block<R>(reader: &mut R) -> Result<Option<String>, LspError>
where
    R: AsyncBufRead + Unpin,
{
    let mut block = String::new();
    loop {
        let budget = MAX_HEADER_BYTES.saturating_sub(block.len());
        let Some(line) = read_bounded_line(reader, budget).await? else {
            return if block.is_empty() {
                Ok(None)
            } else {
                Err(LspError::TruncatedMessage)
            };
        };
        let line = line.strip_suffix(b"\r").unwrap_or(&line);
        if line.is_empty() {
            return Ok(Some(block));
        }
        let text = std::str::from_utf8(line)
            .map_err(|_| LspError::Header("header block was not valid utf-8".into()))?;
        block.push_str(text);
        block.push_str("\r\n");
    }
}

/// Read one `\n`-terminated line, refusing before buffering more than `budget` bytes.
///
/// `AsyncBufReadExt::read_line` cannot be used here. It grows its `String` until it finds a
/// newline or hits EOF, so a peer that sends one enormous header line with no newline makes us
/// allocate all of it *before* any ceiling can be consulted. Checking the size after the read
/// returns the correct error while the memory has already been spent, which is the failure this
/// avoids: the ceiling has to bound the read, not just the verdict.
///
/// Returns `Ok(None)` only at a clean EOF with nothing buffered.
async fn read_bounded_line<R>(reader: &mut R, budget: usize) -> Result<Option<Vec<u8>>, LspError>
where
    R: AsyncBufRead + Unpin,
{
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| LspError::Io(e.to_string()))?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                // A header line that ends at EOF has no terminator, so the block never closed.
                Err(LspError::TruncatedMessage)
            };
        }

        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if line.len() + newline > budget {
                return Err(LspError::HeaderTooLarge {
                    limit: MAX_HEADER_BYTES,
                });
            }
            line.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            return Ok(Some(line));
        }

        // No newline in what is buffered: refuse before copying it, so nothing is consumed and
        // the caller can see how little of a hostile stream was read.
        if line.len() + available.len() > budget {
            return Err(LspError::HeaderTooLarge {
                limit: MAX_HEADER_BYTES,
            });
        }
        let consumed = available.len();
        line.extend_from_slice(available);
        reader.consume(consumed);
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
    async fn a_single_oversized_header_line_stops_reading_at_the_bound() {
        // The bound above is checked *between* lines, so many short lines trip it. One enormous
        // line with no newline is the case that matters: the reader must refuse it without first
        // pulling the whole thing into memory. Asserting the error is not enough -- the error was
        // already correct while the allocation was not -- so this asserts how far the stream was
        // consumed.
        let mut flood = b"X-Pad: ".to_vec();
        flood.resize(MAX_HEADER_BYTES * 4, b'a');
        let total = flood.len();
        let mut r = cursor(&flood);

        assert_eq!(
            read_message(&mut r).await,
            Err(LspError::HeaderTooLarge {
                limit: MAX_HEADER_BYTES
            })
        );
        let consumed = r.position() as usize;
        assert!(
            consumed <= MAX_HEADER_BYTES * 2,
            "refused after consuming {consumed} of {total} bytes; the ceiling must bound the \
             read, not just the verdict"
        );
    }

    #[tokio::test]
    async fn a_deeply_nested_body_is_refused_before_a_dom_is_built() {
        // Two bytes per level on the wire, a whole `Value` node with its own allocation per level
        // in memory: a body well inside the byte ceiling can still amplify far past it.
        let deep = format!("{}{}", "[".repeat(500), "]".repeat(500));
        let mut r = cursor(&encode(&deep));
        assert_eq!(
            read_message(&mut r).await,
            Err(LspError::TooDeep {
                limit: MAX_JSON_DEPTH
            })
        );
    }

    #[tokio::test]
    async fn brackets_inside_a_string_are_text_not_structure() {
        // Most of what a language server sends is code, and code is full of brackets. Counting
        // them would reject legitimate payloads.
        let body =
            serde_json::json!({ "snippet": "fn f() { let v = vec![[1],[2]]; }" }).to_string();
        let mut r = cursor(&encode(&body));
        let value = read_message(&mut r).await.unwrap().unwrap();
        assert!(value["snippet"].as_str().unwrap().contains("vec!"));
    }

    #[tokio::test]
    async fn an_escaped_quote_does_not_end_the_string_scan() {
        let body = serde_json::json!({ "s": r#"he said "[[[" and left"# }).to_string();
        let mut r = cursor(&encode(&body));
        assert!(read_message(&mut r).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn invalid_utf8_body_is_typed_not_lossy() {
        let mut bytes = b"Content-Length: 4\r\n\r\n".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]);
        let mut r = cursor(&bytes);
        assert_eq!(read_message(&mut r).await, Err(LspError::InvalidUtf8));
    }
}
