//! Bounded LSP/HTTP-style header parsing.

use crate::{LspError, MAX_HEADER_BYTES};

/// Parse a header block that has already been split off the stream.
///
/// Only `Content-Length` is load-bearing. `Content-Type` is optional, but an explicitly declared
/// charset must be UTF-8. Unknown extension headers with valid HTTP field-name grammar are ignored
/// because the protocol permits them.
pub fn parse_headers(block: &str) -> Result<usize, LspError> {
    if block.len() > MAX_HEADER_BYTES {
        return Err(LspError::HeaderTooLarge {
            limit: MAX_HEADER_BYTES,
        });
    }
    if !block.is_ascii() {
        return Err(LspError::Header("header block was not ASCII".into()));
    }
    let mut content_length = None;
    let mut content_type_seen = false;
    for line in block.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| LspError::Header(format!("no colon in {line:?}")))?;
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(LspError::Header("invalid header name".into()));
        }
        if value
            .bytes()
            .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
        {
            return Err(LspError::Header("control byte in header value".into()));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(LspError::Header(format!("Content-Length {value:?}")));
            }
            let parsed: usize = value
                .parse()
                .map_err(|_| LspError::Header(format!("Content-Length {value:?}")))?;
            // Even identical duplicates are refused so this parser and any intermediary cannot
            // disagree about whether the first or last field is authoritative.
            if content_length.is_some() {
                return Err(LspError::Header("multiple Content-Length fields".into()));
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type_seen {
                return Err(LspError::Header("multiple Content-Type fields".into()));
            }
            validate_content_type(value.trim())?;
            content_type_seen = true;
        }
    }
    content_length.ok_or(LspError::MissingContentLength)
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_content_type(value: &str) -> Result<(), LspError> {
    let mut parts = value.split(';');
    let media_type = parts.next().unwrap_or_default().trim();
    let Some((kind, subtype)) = media_type.split_once('/') else {
        return Err(LspError::Header("invalid Content-Type media type".into()));
    };
    if kind.is_empty()
        || subtype.is_empty()
        || !kind.bytes().all(is_tchar)
        || !subtype.bytes().all(is_tchar)
    {
        return Err(LspError::Header("invalid Content-Type media type".into()));
    }

    let mut charset_seen = false;
    for parameter in parts {
        let parameter = parameter.trim();
        let Some((name, raw_value)) = parameter.split_once('=') else {
            return Err(LspError::Header("invalid Content-Type parameter".into()));
        };
        let name = name.trim();
        let raw_value = raw_value.trim();
        if name.is_empty() || !name.bytes().all(is_tchar) || raw_value.is_empty() {
            return Err(LspError::Header("invalid Content-Type parameter".into()));
        }
        let parameter_value = if raw_value.starts_with('"') || raw_value.ends_with('"') {
            if raw_value.len() < 2
                || !raw_value.starts_with('"')
                || !raw_value.ends_with('"')
                || raw_value[1..raw_value.len() - 1]
                    .bytes()
                    .any(|byte| matches!(byte, b'"' | b'\\'))
            {
                return Err(LspError::Header(
                    "invalid quoted Content-Type parameter".into(),
                ));
            }
            &raw_value[1..raw_value.len() - 1]
        } else {
            if !raw_value.bytes().all(is_tchar) {
                return Err(LspError::Header(
                    "invalid Content-Type parameter value".into(),
                ));
            }
            raw_value
        };
        if name.eq_ignore_ascii_case("charset") {
            if charset_seen {
                return Err(LspError::Header(
                    "multiple Content-Type charset parameters".into(),
                ));
            }
            if !parameter_value.eq_ignore_ascii_case("utf-8")
                && !parameter_value.eq_ignore_ascii_case("utf8")
            {
                return Err(LspError::Header(format!(
                    "unsupported Content-Type charset {parameter_value:?}"
                )));
            }
            charset_seen = true;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_are_case_insensitive_and_ignore_unknowns() {
        let block =
            "content-length: 42\r\nContent-Type: application/vscode-jsonrpc\r\nX-Odd: 1\r\n";
        assert_eq!(parse_headers(block).unwrap(), 42);
    }

    #[test]
    fn content_type_allows_only_the_protocols_utf8_charset_spellings() {
        for content_type in [
            "application/vscode-jsonrpc",
            "application/vscode-jsonrpc; charset=utf8",
            "application/vscode-jsonrpc; charset=UTF-8",
            "application/vscode-jsonrpc; charset=\"utf-8\"",
            "application/vscode-jsonrpc; profile=vendor; charset=utf8",
        ] {
            let block = format!("Content-Length: 0\r\nContent-Type: {content_type}\r\n");
            assert_eq!(parse_headers(&block), Ok(0), "{content_type:?}");
        }

        for content_type in [
            "application/vscode-jsonrpc; charset=latin1",
            "application/vscode-jsonrpc; charset=utf-16",
            "application/vscode-jsonrpc; charset=",
            "application/vscode-jsonrpc; charset=utf8; charset=utf-8",
        ] {
            let block = format!("Content-Length: 0\r\nContent-Type: {content_type}\r\n");
            assert!(matches!(parse_headers(&block), Err(LspError::Header(_))));
        }
        assert!(matches!(
            parse_headers(
                "Content-Length: 0\r\nContent-Type: application/vscode-jsonrpc\r\nContent-Type: application/vscode-jsonrpc\r\n"
            ),
            Err(LspError::Header(_))
        ));
    }

    #[test]
    fn extension_header_names_accept_the_full_http_tchar_set() {
        let block = "Content-Length: 0\r\n!#$%&'*+-.^_`|~AZaz09: extension\r\n";
        assert_eq!(parse_headers(block), Ok(0));
        assert!(matches!(
            parse_headers("Content-Length: 0\r\nBad(Name): extension\r\n"),
            Err(LspError::Header(_))
        ));
    }

    #[test]
    fn conflicting_content_length_is_refused() {
        let block = "Content-Length: 10\r\nContent-Length: 20\r\n";
        assert_eq!(
            parse_headers(block),
            Err(LspError::Header("multiple Content-Length fields".into()))
        );
    }

    #[test]
    fn repeated_identical_content_length_is_also_refused() {
        assert_eq!(
            parse_headers("Content-Length: 10\r\nContent-Length: 10\r\n"),
            Err(LspError::Header("multiple Content-Length fields".into()))
        );
    }

    #[test]
    fn header_grammar_rejects_parser_ambiguity() {
        for block in [
            "Content-Length: +1",
            "Content Length: 1",
            "Content-Length: 1\nX-Test: yes",
            "Content-Length: 1\0",
            "Content-Length: 1界",
        ] {
            assert!(matches!(parse_headers(block), Err(LspError::Header(_))));
        }
    }

    #[test]
    fn missing_content_length_is_typed() {
        assert_eq!(
            parse_headers("Content-Type: application/vscode-jsonrpc\r\n"),
            Err(LspError::MissingContentLength)
        );
    }
}
