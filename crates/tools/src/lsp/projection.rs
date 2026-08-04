use super::LspToolError;
use core_lsp::MAX_HOVER_BYTES;
use core_lsp::intel::{parse_hover_text, parse_locations};
use serde_json::{Value, json};
use std::path::Path;

/// Project server-owned locations into workspace-relative identities. Absolute host paths,
/// dependency paths and non-file virtual URIs are counted but never copied into model context.
pub(super) fn locations(
    value: &Value,
    limit: usize,
    canonical_root: &Path,
) -> Result<Value, LspToolError> {
    let parsed = parse_locations(value, limit)?;
    let mut retained = Vec::with_capacity(parsed.locations.len());
    let mut outside_workspace = 0usize;
    let mut lossy_paths = 0usize;
    for location in parsed.locations {
        let Some(relative) = workspace_relative(location.uri(), canonical_root) else {
            outside_workspace = outside_workspace.saturating_add(1);
            continue;
        };
        let (path, lossy) = match relative.to_str() {
            Some(path) => (path.to_owned(), false),
            None => (relative.to_string_lossy().into_owned(), true),
        };
        lossy_paths = lossy_paths.saturating_add(usize::from(lossy));
        retained.push(json!({"path": path, "range": location.range()}));
    }
    Ok(json!({
        "locations": retained,
        "truncated": parsed.truncated,
        "malformed": parsed.malformed,
        "duplicates": parsed.duplicates,
        "uninspected": parsed.uninspected,
        "outside_workspace": outside_workspace,
        "lossy_paths": lossy_paths
    }))
}

/// Redact the known workspace root from hover text while retaining the pure parser's source-byte
/// accounting as explicitly pre-redaction fields.
pub(super) fn hover(value: &Value, canonical_root: &Path) -> Value {
    let parsed = parse_hover_text(value);
    let redacted = parsed
        .text
        .map(|text| redact_host_paths(&text, canonical_root));
    let text = redacted.as_ref().map(|redacted| redacted.text.clone());
    let workspace_path_redactions = redacted
        .as_ref()
        .map_or(0, |redacted| redacted.workspace_paths);
    let absolute_path_redactions = redacted
        .as_ref()
        .map_or(0, |redacted| redacted.absolute_paths);
    let projection_truncated = redacted.as_ref().is_some_and(|redacted| redacted.truncated);
    json!({
        "text": text,
        "range": parsed.range,
        "peer_source_bytes": parsed.source_bytes,
        "peer_retained_source_bytes": parsed.retained_source_bytes,
        "peer_truncated_bytes": parsed.truncated_bytes,
        "separator_bytes": parsed.separator_bytes,
        "malformed": parsed.malformed,
        "uninspected": parsed.uninspected,
        "workspace_path_redactions": workspace_path_redactions,
        "absolute_path_redactions": absolute_path_redactions,
        "projection_truncated": projection_truncated
    })
}

fn workspace_relative(uri: &str, canonical_root: &Path) -> Option<std::path::PathBuf> {
    let url = url::Url::parse(uri).ok()?;
    if url.scheme() != "file" {
        return None;
    }
    let lexical_path = url.to_file_path().ok()?;
    // Reject an external lexical target before any filesystem lookup. A hostile server must not
    // turn a location URI into an existence/symlink probe outside the workspace.
    if !lexical_path.starts_with(canonical_root) {
        return None;
    }
    let path = lexical_path.canonicalize().ok()?;
    path.strip_prefix(canonical_root)
        .ok()
        .map(Path::to_path_buf)
}

struct RedactedHover {
    text: String,
    workspace_paths: usize,
    absolute_paths: usize,
    truncated: bool,
}

fn redact_host_paths(text: &str, canonical_root: &Path) -> RedactedHover {
    let root = canonical_root.to_string_lossy();
    let root = (!root.is_empty() && root != "/").then_some(root.as_ref());
    let root_uri = root.and_then(|_| {
        url::Url::from_directory_path(canonical_root)
            .ok()
            .map(|url| url.to_string())
    });
    let mut result = RedactedHover {
        text: String::with_capacity(text.len().min(MAX_HOVER_BYTES)),
        workspace_paths: 0,
        absolute_paths: 0,
        truncated: false,
    };
    let mut offset = 0usize;
    while offset < text.len() {
        if result.text.len() == MAX_HOVER_BYTES {
            result.truncated = true;
            break;
        }
        let remaining = &text[offset..];
        if let Some(uri) = root_uri
            .as_deref()
            .filter(|uri| remaining.starts_with(*uri))
        {
            result.workspace_paths = result.workspace_paths.saturating_add(1);
            push_bounded(&mut result, "<workspace>/");
            offset = offset.saturating_add(uri.len());
            continue;
        }
        if let Some(root) = root.filter(|root| remaining.starts_with(*root)) {
            result.workspace_paths = result.workspace_paths.saturating_add(1);
            push_bounded(&mut result, "<workspace>");
            offset = offset.saturating_add(root.len());
            continue;
        }
        if absolute_path_starts(text, offset) {
            result.absolute_paths = result.absolute_paths.saturating_add(1);
            push_bounded(&mut result, "<absolute-path>");
            offset = consume_path_token(text, offset);
            continue;
        }
        let character = remaining.chars().next().expect("offset is in bounds");
        let mut encoded = [0_u8; 4];
        push_bounded(&mut result, character.encode_utf8(&mut encoded));
        offset = offset.saturating_add(character.len_utf8());
    }
    result
}

fn absolute_path_starts(text: &str, offset: usize) -> bool {
    let remaining = &text[offset..];
    let boundary = offset == 0
        || text[..offset]
            .chars()
            .next_back()
            .is_some_and(is_path_boundary);
    if !boundary {
        return false;
    }
    // Do not reinterpret the `//` after an ordinary URI scheme as a host path. `file://` is
    // handled explicitly below because it does carry a local identity.
    if remaining.starts_with("//") && preceding_uri_scheme(text, offset) {
        return false;
    }
    if remaining.starts_with("file://")
        || remaining.starts_with("~/")
        || remaining.starts_with("~\\")
        || tilde_user_path_starts(remaining)
        || remaining.starts_with("\\\\")
    {
        return true;
    }
    if remaining.starts_with('/') {
        return remaining
            .chars()
            .nth(1)
            .is_some_and(|character| !character.is_whitespace());
    }
    let mut characters = remaining.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
        && characters.next() == Some(':')
        && characters
            .next()
            .is_some_and(|character| matches!(character, '/' | '\\'))
}

fn preceding_uri_scheme(text: &str, offset: usize) -> bool {
    let Some(prefix) = text
        .get(..offset)
        .and_then(|prefix| prefix.strip_suffix(':'))
    else {
        return false;
    };
    let scheme = prefix
        .rsplit_once(|character: char| {
            !character.is_ascii_alphanumeric()
                && character != '+'
                && character != '-'
                && character != '.'
        })
        .map_or(prefix, |(_, scheme)| scheme);
    !scheme.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic())
        && scheme.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

fn tilde_user_path_starts(remaining: &str) -> bool {
    let Some(rest) = remaining.strip_prefix('~') else {
        return false;
    };
    let mut saw_user = false;
    for character in rest.chars() {
        if matches!(character, '/' | '\\') {
            return saw_user;
        }
        if !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-')) {
            return false;
        }
        saw_user = true;
    }
    false
}

fn is_path_boundary(character: char) -> bool {
    !character.is_alphanumeric() && !matches!(character, '_' | '-' | '.' | '/' | '\\')
}

fn consume_path_token(text: &str, offset: usize) -> usize {
    if let Some(delimiter) = text[..offset]
        .chars()
        .next_back()
        .filter(|character| matches!(character, '`' | '"' | '\''))
    {
        let mut end = text.len();
        for (relative, character) in text[offset..].char_indices() {
            if character == delimiter || matches!(character, '\n' | '\r') || character.is_control()
            {
                end = offset.saturating_add(relative);
                break;
            }
        }
        return end.max(offset.saturating_add(1));
    }
    let mut end = offset;
    for (relative, character) in text[offset..].char_indices() {
        if relative > 0
            && (character.is_whitespace()
                || character.is_control()
                || matches!(character, ')' | ']' | '}' | '>' | '"' | '\'' | ',' | ';'))
        {
            break;
        }
        end = offset
            .saturating_add(relative)
            .saturating_add(character.len_utf8());
    }
    end.max(offset.saturating_add(1))
}

fn push_bounded(result: &mut RedactedHover, value: &str) {
    let remaining = MAX_HOVER_BYTES.saturating_sub(result.text.len());
    if remaining == 0 {
        result.truncated = true;
        return;
    }
    let mut end = value.len().min(remaining);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    result.text.push_str(&value[..end]);
    result.truncated |= end < value.len();
}

#[cfg(test)]
mod tests {
    use super::redact_host_paths;
    use std::path::Path;

    #[test]
    fn redacts_known_workspace_and_other_absolute_path_tokens() {
        let redacted = redact_host_paths(
            "see /repo/private/src/lib.rs, /other/file, file:///secret/x, C:\\Users\\x and safe/path",
            Path::new("/repo/private"),
        );
        assert_eq!(
            redacted.text,
            "see <workspace>/src/lib.rs, <absolute-path>, <absolute-path>, <absolute-path> and safe/path"
        );
        assert_eq!(redacted.workspace_paths, 1);
        assert_eq!(redacted.absolute_paths, 3);
        assert!(!redacted.truncated);
    }

    #[test]
    fn redacts_paths_adjacent_to_markdown_delimiters() {
        let redacted = redact_host_paths(
            "`/home/user/private`\n```\n/etc/secret\n```\n*/opt/key* |/var/lib/x| [x](/srv/repo) !C:\\Users\\name \\\\server\\share",
            Path::new("/workspace"),
        );
        for secret in [
            "/home/user/private",
            "/etc/secret",
            "/opt/key",
            "/var/lib/x",
            "/srv/repo",
            "C:\\Users\\name",
            "\\\\server\\share",
        ] {
            assert!(!redacted.text.contains(secret), "leaked {secret:?}");
        }
        assert_eq!(redacted.absolute_paths, 7);
    }

    #[test]
    fn redacts_quoted_paths_with_spaces_and_named_home_paths_without_leaking_suffixes() {
        let redacted = redact_host_paths(
            "\"/Volumes/Client Drive/Secret Project/key\" `C:\\Users\\Client Name\\secret.txt` '~alice/private notes/key' \\\\server\\share and ~bob/private/key",
            Path::new("/workspace"),
        );
        for secret in [
            "Client Drive",
            "Secret Project",
            "Client Name",
            "private notes",
            "alice",
            "bob",
        ] {
            assert!(!redacted.text.contains(secret), "leaked {secret:?}");
        }
        assert_eq!(redacted.absolute_paths, 5);
    }

    #[test]
    fn preserves_non_file_documentation_urls() {
        let redacted = redact_host_paths(
            "see https://example.com/reference and ssh://host/path",
            Path::new("/workspace"),
        );
        assert_eq!(
            redacted.text,
            "see https://example.com/reference and ssh://host/path"
        );
        assert_eq!(redacted.absolute_paths, 0);
    }
}
