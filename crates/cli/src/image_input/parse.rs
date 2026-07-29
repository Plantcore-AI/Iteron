use super::{ImageInputError, ImageInputErrorKind, ImageMention, ParsedImagePath, SafeDisplayName};
use crate::image_input::sniff::extension_media_type;
use core_protocol::input::MAX_INPUT_IMAGES;
use core_protocol::task::MAX_TASK_TEXT_BYTES;
use std::path::PathBuf;
use url::Url;

const MAX_PATH_INPUT_BYTES: usize = 4 * 1024;

pub fn parse_explicit_image_path(input: &str) -> Result<Option<ParsedImagePath>, ImageInputError> {
    if input.len() > MAX_PATH_INPUT_BYTES || input.contains(['\r', '\n', '\0']) {
        return Ok(None);
    }
    let Some(candidate) = decode_single_path_token(input.trim()) else {
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
                .take(MAX_PATH_INPUT_BYTES + 1)
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
        if offset > MAX_PATH_INPUT_BYTES {
            return None;
        }
        if character.is_whitespace() || ",;!?)]}".contains(character) {
            return Some(offset);
        }
    }
    (input.len() <= MAX_PATH_INPUT_BYTES).then_some(input.len())
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
            || candidate.chars().any(char::is_control)
        {
            return Ok(None);
        }
        PathBuf::from(candidate)
    };
    if extension_media_type(&path).is_none() {
        return Ok(None);
    }
    Ok(Some(ParsedImagePath {
        display_name: SafeDisplayName::from_path(&path),
        path,
    }))
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
        return decode_backslash_token(inner, true);
    }
    decode_backslash_token(input, false)
}

fn decode_backslash_token(input: &str, quoted: bool) -> Option<String> {
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
    use super::decode_backslash_token;

    #[test]
    fn unix_drag_drop_escapes_remain_conservative() {
        assert_eq!(
            decode_backslash_token(r"My\ Screenshot.webp", false).as_deref(),
            Some("My Screenshot.webp")
        );
        assert!(decode_backslash_token(r"bad\q.png", false).is_none());
    }
}
