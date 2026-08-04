use super::LspToolError;
use crate::write_file::{TargetSnapshot, capture_target_snapshot, read_existing_snapshot};
use core_lsp::intel::Position;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

pub(super) const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REQUEST_PATH_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Adapter {
    Rust,
    TypeScript,
    Python,
}

impl Adapter {
    pub(super) fn for_path(path: &Path) -> Result<Self, LspToolError> {
        match path.extension().and_then(|value| value.to_str()) {
            Some("rs") => Ok(Self::Rust),
            Some("ts" | "tsx" | "js" | "jsx") => Ok(Self::TypeScript),
            Some("py" | "pyi") => Ok(Self::Python),
            _ => Err(LspToolError::UnsupportedLanguage),
        }
    }

    pub(super) const fn command(self) -> &'static str {
        match self {
            Self::Rust => "rust-analyzer",
            Self::TypeScript => "typescript-language-server --stdio",
            Self::Python => "pyright-langserver --stdio",
        }
    }

    pub(super) const fn server_label(self) -> &'static str {
        match self {
            Self::Rust => "rust-analyzer",
            Self::TypeScript => "typescript-language-server",
            Self::Python => "pyright-langserver",
        }
    }

    pub(super) const fn language_id(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "typescript",
            Self::Python => "python",
        }
    }
}

#[derive(Debug)]
pub(super) struct SourceDocument {
    canonical_root: PathBuf,
    canonical_path: PathBuf,
    uri: String,
    text: String,
    digest: String,
    adapter: Adapter,
    target: TargetSnapshot,
}

impl SourceDocument {
    pub(super) async fn load(root: &Path, requested: &str) -> Result<Self, LspToolError> {
        validate_requested_path(requested)?;
        let canonical_root = root
            .canonicalize()
            .map_err(|_| LspToolError::WorkspaceUnavailable)?;
        let canonical_path = crate::resolve_in_root(&canonical_root, requested)
            .map_err(|_| LspToolError::PathEscapesWorkspace)?;
        if !canonical_path.starts_with(&canonical_root) || !canonical_path.is_file() {
            return Err(LspToolError::PathEscapesWorkspace);
        }
        let adapter = Adapter::for_path(&canonical_path)?;
        let snapshot = read_existing_snapshot(&canonical_path)
            .await
            .map_err(|_| LspToolError::SourceUnavailable)?;
        if snapshot.bytes.len() > MAX_SOURCE_BYTES {
            return Err(LspToolError::SourceTooLarge {
                limit: MAX_SOURCE_BYTES,
            });
        }
        let bytes = snapshot.bytes;
        let text = String::from_utf8(bytes).map_err(|_| LspToolError::SourceNotUtf8)?;
        let digest = digest(text.as_bytes());
        let uri = url::Url::from_file_path(&canonical_path)
            .map_err(|_| LspToolError::InvalidFileUri)?
            .to_string();
        Ok(Self {
            canonical_root,
            canonical_path,
            uri,
            text,
            digest,
            adapter,
            target: snapshot.target,
        })
    }

    pub(super) fn root(&self) -> &Path {
        &self.canonical_root
    }

    pub(super) fn root_uri(&self) -> Result<String, LspToolError> {
        url::Url::from_directory_path(&self.canonical_root)
            .map_err(|_| LspToolError::InvalidFileUri)
            .map(|url| url.to_string())
    }

    pub(super) fn uri(&self) -> &str {
        &self.uri
    }

    pub(super) fn text(&self) -> &str {
        &self.text
    }

    pub(super) fn digest(&self) -> &str {
        &self.digest
    }

    pub(super) fn adapter(&self) -> Adapter {
        self.adapter
    }

    pub(super) fn position(&self, line: u32, character: u32) -> Result<Position, LspToolError> {
        validate_utf16_position(&self.text, line, character)?;
        Position::new(line, character).map_err(LspToolError::Protocol)
    }

    /// Re-open the canonical target and bind the returned context to the same target bytes.
    /// Dependency files remain server-owned observations and are an explicit residual nonclaim.
    pub(super) async fn recheck(&self) -> Result<(), LspToolError> {
        let current = capture_target_snapshot(&self.canonical_path)
            .await
            .map_err(|_| LspToolError::SourceChanged)?;
        if current != self.target {
            return Err(LspToolError::SourceChanged);
        }
        Ok(())
    }
}

fn validate_requested_path(requested: &str) -> Result<(), LspToolError> {
    if requested.is_empty()
        || requested.len() > MAX_REQUEST_PATH_BYTES
        || requested.chars().any(char::is_control)
    {
        return Err(LspToolError::InvalidPath);
    }
    let path = Path::new(requested);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(LspToolError::PathEscapesWorkspace);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_utf16_position(
    text: &str,
    requested_line: u32,
    requested_character: u32,
) -> Result<(), LspToolError> {
    let line = text
        .split('\n')
        .nth(requested_line as usize)
        .ok_or(LspToolError::PositionOutsideDocument)?;
    // LSP positions do not include a line-ending sequence. `split('\n')` preserves the CR half
    // of CRLF, so remove exactly that terminator before counting UTF-16 code units.
    let line = line.strip_suffix('\r').unwrap_or(line);
    let utf16_len = line.encode_utf16().count();
    if requested_character as usize > utf16_len {
        return Err(LspToolError::PositionOutsideDocument);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_utf16_position;

    #[test]
    fn position_uses_lsp_utf16_units_and_rejects_missing_lines() {
        let source = "a😀b\nsecond";
        assert!(validate_utf16_position(source, 0, 4).is_ok());
        assert!(validate_utf16_position(source, 0, 5).is_err());
        assert!(validate_utf16_position(source, 2, 0).is_err());
        assert!(validate_utf16_position("x\r\ny", 0, 1).is_ok());
        assert!(validate_utf16_position("x\r\ny", 0, 2).is_err());
    }
}
