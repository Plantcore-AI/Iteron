use super::{ImageInputError, ImageInputErrorKind, ImageMention, ParsedImagePath, SafeDisplayName};
use crate::image_input::sniff::extension_format;
use iteron_protocol::input::MAX_INPUT_IMAGES;
use iteron_protocol::task::MAX_TASK_TEXT_BYTES;
use std::path::PathBuf;
use url::Url;

const MAX_PATH_INPUT_BYTES: usize = 4 * 1024;

pub fn parse_explicit_image_path(input: &str) -> Result<Option<ParsedImagePath>, ImageInputError> {
    // Surrounding whitespace is dropped before the line-break test, not after: a terminal ends a
    // dropped path with a newline, and rejecting the whole drop for that trailing byte sent the
    // path on to the composer as bare text. An INTERIOR line break still disqualifies it — that is
    // two references, not one.
    let input = input.trim();
    if input.len()
        > iteron_tunables::param_integer(
            "cli.image_input.parse.max_path_input_bytes",
            MAX_PATH_INPUT_BYTES,
        )
        || input.contains(['\r', '\n', '\0'])
    {
        return Ok(None);
    }
    let Some(candidate) = decode_single_path_token(input) else {
        return Ok(None);
    };
    parse_path_candidate(&candidate)
}

pub fn parse_image_mentions(input: &str) -> Result<Vec<ImageMention>, ImageInputError> {
    if input.len() > MAX_TASK_TEXT_BYTES {
        return Err(ImageInputError::unnamed(
            ImageInputErrorKind::InvalidReference,
        ));
    }
    let mut mentions = Vec::new();
    for (start, _) in input.match_indices('@') {
        if !mention_boundary(input, start) {
            continue;
        }
        let tail = &input[start + 1..];
        let (candidate, end) = if let Some(inner) = tail.strip_prefix("image(") {
            let Some(close) = inner
                .as_bytes()
                .iter()
                .take(
                    iteron_tunables::param_integer(
                        "cli.image_input.parse.max_path_input_bytes",
                        MAX_PATH_INPUT_BYTES,
                    ) + 1,
                )
                .position(|byte| *byte == b')')
            else {
                return Err(ImageInputError::unnamed(
                    ImageInputErrorKind::InvalidReference,
                ));
            };
            (&inner[..close], start + 1 + "image(".len() + close + 1)
        } else {
            let Some(end_offset) = bounded_token_end(tail) else {
                continue;
            };
            let raw_token = &tail[..end_offset];
            let trimmed_token = raw_token.trim_end_matches('.');
            let token = trimmed_token
                .strip_prefix("image:")
                .unwrap_or(trimmed_token);
            let token_end = trimmed_token.len();
            (token, start + 1 + token_end)
        };
        if candidate.is_empty() {
            continue;
        }
        if let Some(reference) = parse_explicit_image_path(candidate)? {
            mentions.push(ImageMention {
                byte_range: start..end,
                reference,
            });
            if mentions.len() > MAX_INPUT_IMAGES {
                return Err(ImageInputError::unnamed(
                    ImageInputErrorKind::TooManyMentions,
                ));
            }
        }
    }
    Ok(mentions)
}

fn bounded_token_end(input: &str) -> Option<usize> {
    for (offset, character) in input.char_indices() {
        if offset
            > iteron_tunables::param_integer(
                "cli.image_input.parse.max_path_input_bytes",
                MAX_PATH_INPUT_BYTES,
            )
        {
            return None;
        }
        if character.is_whitespace() || ",;!?)]}".contains(character) {
            return Some(offset);
        }
    }
    (input.len()
        <= iteron_tunables::param_integer(
            "cli.image_input.parse.max_path_input_bytes",
            MAX_PATH_INPUT_BYTES,
        ))
    .then_some(input.len())
}

fn parse_path_candidate(candidate: &str) -> Result<Option<ParsedImagePath>, ImageInputError> {
    let path = if candidate.starts_with("file:") {
        let url = Url::parse(candidate)
            .map_err(|_| ImageInputError::unnamed(ImageInputErrorKind::InvalidReference))?;
        if url.scheme() != "file"
            || url.host_str().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ImageInputError::unnamed(
                ImageInputErrorKind::InvalidReference,
            ));
        }
        url.to_file_path()
            .map_err(|_| ImageInputError::unnamed(ImageInputErrorKind::InvalidReference))?
    } else {
        if candidate.is_empty()
            || candidate.starts_with('-')
            || candidate.starts_with("~/")
            || candidate.contains("://")
            || (cfg!(windows) && is_windows_device_or_network_path(candidate))
            || candidate.chars().any(char::is_control)
        {
            return Ok(None);
        }
        PathBuf::from(candidate)
    };
    if extension_format(&path).is_none() {
        return Ok(None);
    }
    Ok(Some(ParsedImagePath {
        display_name: SafeDisplayName::from_path(&path),
        path,
    }))
}

fn is_windows_device_or_network_path(candidate: &str) -> bool {
    candidate
        .as_bytes()
        .get(..2)
        .is_some_and(|prefix| prefix.iter().all(|byte| matches!(byte, b'\\' | b'/')))
}

fn decode_single_path_token(input: &str) -> Option<String> {
    if input.is_empty() {
        return None;
    }
    if (input.starts_with('"') && input.ends_with('"'))
        || (input.starts_with('\'') && input.ends_with('\''))
    {
        if input.len() < 2 {
            return None;
        }
        let quote = input.as_bytes()[0] as char;
        let inner = &input[1..input.len() - 1];
        if quote == '\'' {
            return (!inner.contains('\'')).then(|| inner.to_owned());
        }
        return decode_backslash_token(inner, true, cfg!(windows));
    }
    decode_backslash_token(input, false, cfg!(windows))
}

fn decode_backslash_token(
    input: &str,
    quoted: bool,
    preserve_windows_separators: bool,
) -> Option<String> {
    if preserve_windows_separators {
        return input
            .chars()
            .all(|character| {
                character != '"' && (quoted || (!character.is_whitespace() && character != '\''))
            })
            .then(|| input.to_owned());
    }

    let mut output = String::with_capacity(input.len());
    let mut escaped = false;
    for character in input.chars() {
        if escaped {
            if !matches!(character, '\\' | '"' | '\'' | ' ') {
                return None;
            }
            output.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if !quoted && (matches!(character, '"' | '\'') || character.is_whitespace()) {
            return None;
        } else {
            output.push(character);
        }
    }
    (!escaped).then_some(output)
}

fn mention_boundary(input: &str, at: usize) -> bool {
    input[..at]
        .chars()
        .next_back()
        .is_none_or(|character| character.is_whitespace() || "([{'\"".contains(character))
}

#[cfg(test)]
mod tests {
    use super::{decode_backslash_token, is_windows_device_or_network_path};

    #[test]
    fn native_windows_separators_are_paths_not_escape_prefixes() {
        assert_eq!(
            decode_backslash_token(r"C:\Users\operator\shot.png", false, true).as_deref(),
            Some(r"C:\Users\operator\shot.png")
        );
        assert_eq!(
            decode_backslash_token(r"C:\Users\operator\My Screenshot.jpeg", true, true).as_deref(),
            Some(r"C:\Users\operator\My Screenshot.jpeg")
        );
        assert!(decode_backslash_token(r"C:\My Screenshot.png", false, true).is_none());
        assert!(decode_backslash_token(r#"C:\bad"name.png"#, false, true).is_none());
        assert!(is_windows_device_or_network_path(
            r"\\server\share\shot.png"
        ));
        assert!(is_windows_device_or_network_path("//server/share/shot.png"));
        assert!(is_windows_device_or_network_path(
            r"\/server/share/shot.png"
        ));
        assert!(is_windows_device_or_network_path(r"\\.\pipe\shot.png"));
        assert!(!is_windows_device_or_network_path(
            r"C:\Users\operator\shot.png"
        ));
    }

    #[test]
    fn unix_drag_drop_escapes_remain_conservative() {
        assert_eq!(
            decode_backslash_token(r"My\ Screenshot.webp", false, false).as_deref(),
            Some("My Screenshot.webp")
        );
        assert!(decode_backslash_token(r"bad\q.png", false, false).is_none());
    }
}
