use super::LspToolError;
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
    let (text, workspace_path_redactions) = parsed
        .text
        .map(|text| redact_workspace_path(text, canonical_root))
        .map_or((None, 0), |(text, count)| (Some(text), count));
    json!({
        "text": text,
        "range": parsed.range,
        "peer_source_bytes": parsed.source_bytes,
        "peer_retained_source_bytes": parsed.retained_source_bytes,
        "peer_truncated_bytes": parsed.truncated_bytes,
        "separator_bytes": parsed.separator_bytes,
        "malformed": parsed.malformed,
        "uninspected": parsed.uninspected,
        "workspace_path_redactions": workspace_path_redactions
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

fn redact_workspace_path(text: String, canonical_root: &Path) -> (String, usize) {
    let root = canonical_root.to_string_lossy();
    if root.is_empty() || root == "/" {
        return (text, 0);
    }
    let root_uri = url::Url::from_directory_path(canonical_root)
        .ok()
        .map(|url| url.to_string());
    let mut count = 0usize;
    let mut redacted = text;
    if let Some(root_uri) = root_uri {
        let uri_count = redacted.matches(&root_uri).count();
        count = count.saturating_add(uri_count);
        redacted = redacted.replace(&root_uri, "<workspace>/");
    }
    let path_count = redacted.matches(root.as_ref()).count();
    count = count.saturating_add(path_count);
    redacted = redacted.replace(root.as_ref(), "<workspace>");
    (redacted, count)
}

#[cfg(test)]
mod tests {
    use super::redact_workspace_path;
    use std::path::Path;

    #[test]
    fn redacts_known_workspace_without_rewriting_slashes_globally() {
        let (text, count) = redact_workspace_path(
            "see /repo/private/src/lib.rs and /other/file".into(),
            Path::new("/repo/private"),
        );
        assert_eq!(text, "see <workspace>/src/lib.rs and /other/file");
        assert_eq!(count, 1);
    }
}
