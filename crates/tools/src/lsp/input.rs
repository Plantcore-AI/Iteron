use super::LspToolError;
use iteron_lsp::intel::Position;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Component, Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use super::capability::{FileStamp, RootBinding, SourceBinding};
#[cfg(unix)]
use tokio::io::AsyncReadExt as _;

pub(super) const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REQUEST_PATH_BYTES: usize = 4 * 1024;
#[cfg(unix)]
const SOURCE_READ_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Adapter {
    Rust,
    TypeScript,
    TypeScriptReact,
    JavaScript,
    JavaScriptReact,
    Python,
}

impl Adapter {
    pub(super) fn for_path(path: &Path) -> Result<Self, LspToolError> {
        match path.extension().and_then(|value| value.to_str()) {
            Some("rs") => Ok(Self::Rust),
            Some("ts") => Ok(Self::TypeScript),
            Some("tsx") => Ok(Self::TypeScriptReact),
            Some("js") => Ok(Self::JavaScript),
            Some("jsx") => Ok(Self::JavaScriptReact),
            Some("py" | "pyi") => Ok(Self::Python),
            _ => Err(LspToolError::UnsupportedLanguage),
        }
    }

    pub(super) const fn command(self) -> &'static str {
        match self {
            Self::Rust => "rust-analyzer",
            Self::TypeScript | Self::TypeScriptReact | Self::JavaScript | Self::JavaScriptReact => {
                "typescript-language-server --stdio"
            }
            Self::Python => "pyright-langserver --stdio",
        }
    }

    pub(super) const fn server_label(self) -> &'static str {
        match self {
            Self::Rust => "rust-analyzer",
            Self::TypeScript | Self::TypeScriptReact | Self::JavaScript | Self::JavaScriptReact => {
                "typescript-language-server"
            }
            Self::Python => "pyright-langserver",
        }
    }

    pub(super) const fn language_id(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "typescript",
            Self::TypeScriptReact => "typescriptreact",
            Self::JavaScript => "javascript",
            Self::JavaScriptReact => "javascriptreact",
            Self::Python => "python",
        }
    }
}

#[derive(Debug)]
pub(super) struct SourceDocument {
    requested_root: PathBuf,
    canonical_root: PathBuf,
    uri: String,
    text: String,
    digest: String,
    adapter: Adapter,
    command: String,
    server_label: String,
    #[cfg(unix)]
    root_binding: RootBinding,
    #[cfg(unix)]
    source_binding: SourceBinding,
}

impl SourceDocument {
    pub(super) async fn load(
        root: &Path,
        requested: &str,
        routes: &BTreeMap<String, String>,
    ) -> Result<Self, LspToolError> {
        #[cfg(not(unix))]
        {
            let _ = (root, requested);
            return Err(LspToolError::SandboxUnavailable);
        }

        #[cfg(unix)]
        {
            validate_requested_path(requested)?;
            let requested_root = if root.is_absolute() {
                root.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|_| LspToolError::WorkspaceUnavailable)?
                    .join(root)
            };
            let canonical_root = requested_root
                .canonicalize()
                .map_err(|_| LspToolError::WorkspaceUnavailable)?;
            let root_binding = RootBinding::open(&canonical_root)
                .map_err(|_| LspToolError::WorkspaceUnavailable)?;
            let relative_path = PathBuf::from(requested);
            let canonical_path = canonical_root.join(&relative_path);
            let adapter = Adapter::for_path(&relative_path)?;
            let command = routes
                .get(adapter.language_id())
                .cloned()
                .unwrap_or_else(|| adapter.command().to_owned());
            let server_label = if routes.contains_key(adapter.language_id()) {
                format!("plugin:{}", adapter.language_id())
            } else {
                adapter.server_label().to_owned()
            };
            let source_binding = root_binding
                .bind_source(&relative_path)
                .map_err(|_| LspToolError::SourceUnavailable)?;
            let (bytes, target_stamp) = read_bounded(
                source_binding
                    .file()
                    .map_err(|_| LspToolError::SourceUnavailable)?,
            )
            .await?;
            if requested_root.canonicalize().ok().as_deref() != Some(canonical_root.as_path())
                || target_stamp != *source_binding.stamp()
                || !source_binding.still_visible(&root_binding)
            {
                return Err(LspToolError::SourceChanged);
            }
            if bytes.len() > MAX_SOURCE_BYTES {
                return Err(LspToolError::SourceTooLarge {
                    limit: MAX_SOURCE_BYTES,
                });
            }
            let text = String::from_utf8(bytes).map_err(|_| LspToolError::SourceNotUtf8)?;
            let digest = digest(text.as_bytes());
            let uri = url::Url::from_file_path(&canonical_path)
                .map_err(|_| LspToolError::InvalidFileUri)?
                .to_string();
            Ok(Self {
                requested_root,
                canonical_root,
                uri,
                text,
                digest,
                adapter,
                command,
                server_label,
                root_binding,
                source_binding,
            })
        }
    }

    pub(super) fn root(&self) -> &Path {
        &self.canonical_root
    }

    #[cfg(unix)]
    pub(super) fn root_capability(&self) -> Result<&File, LspToolError> {
        Ok(self.root_binding.root())
    }

    #[cfg(not(unix))]
    pub(super) fn root_capability(&self) -> Result<&File, LspToolError> {
        Err(LspToolError::SandboxUnavailable)
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

    pub(super) fn command(&self) -> &str {
        &self.command
    }

    pub(super) fn server_label(&self) -> &str {
        &self.server_label
    }

    pub(super) fn position(&self, line: u32, character: u32) -> Result<Position, LspToolError> {
        validate_utf16_position(&self.text, line, character)?;
        Position::new(line, character).map_err(LspToolError::Protocol)
    }

    /// Re-open the canonical target and bind the returned context to the same target bytes.
    /// Dependency files remain server-owned observations and are an explicit residual nonclaim.
    pub(super) async fn recheck(&self) -> Result<(), LspToolError> {
        #[cfg(unix)]
        {
            let visible_root = self
                .requested_root
                .canonicalize()
                .map_err(|_| LspToolError::SourceChanged)?;
            if visible_root != self.canonical_root
                || !self.source_binding.still_visible(&self.root_binding)
            {
                return Err(LspToolError::SourceChanged);
            }
            let source = self
                .source_binding
                .file()
                .map_err(|_| LspToolError::SourceChanged)?;
            let (bytes, stamp) = read_bounded(source)
                .await
                .map_err(|_| LspToolError::SourceChanged)?;
            if stamp != *self.source_binding.stamp() || digest(&bytes) != self.digest {
                return Err(LspToolError::SourceChanged);
            }
            if !self.source_binding.still_visible(&self.root_binding) {
                return Err(LspToolError::SourceChanged);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(LspToolError::SandboxUnavailable)
        }
    }
}

#[cfg(unix)]
async fn read_bounded(file: File) -> Result<(Vec<u8>, FileStamp), LspToolError> {
    let before = FileStamp::capture(&file).map_err(|_| LspToolError::SourceUnavailable)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut bytes = Vec::with_capacity((MAX_SOURCE_BYTES + 1).min(64 * 1024));
    let read = async {
        let mut limited = tokio::io::AsyncReadExt::take(&mut file, (MAX_SOURCE_BYTES + 1) as u64);
        limited.read_to_end(&mut bytes).await
    };
    tokio::time::timeout(SOURCE_READ_TIMEOUT, read)
        .await
        .map_err(|_| LspToolError::SourceUnavailable)?
        .map_err(|_| LspToolError::SourceUnavailable)?;
    let file = file.into_std().await;
    let after = FileStamp::capture(&file).map_err(|_| LspToolError::SourceUnavailable)?;
    if before != after {
        return Err(LspToolError::SourceChanged);
    }
    Ok((bytes, after))
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
    let requested = requested_character as usize;
    let mut boundary = 0usize;
    if requested == 0 {
        return Ok(());
    }
    for character in line.chars() {
        boundary = boundary.saturating_add(character.len_utf16());
        if requested == boundary {
            return Ok(());
        }
        if requested < boundary {
            return Err(LspToolError::PositionOutsideDocument);
        }
    }
    Err(LspToolError::PositionOutsideDocument)
}

#[cfg(test)]
mod tests {
    use super::{Adapter, validate_utf16_position};
    use std::path::Path;

    #[test]
    fn javascript_family_uses_the_exact_lsp_language_id() {
        for (path, expected) in [
            ("source.ts", "typescript"),
            ("source.tsx", "typescriptreact"),
            ("source.js", "javascript"),
            ("source.jsx", "javascriptreact"),
        ] {
            let adapter = Adapter::for_path(Path::new(path)).unwrap();
            assert_eq!(adapter.language_id(), expected, "wrong id for {path}");
            assert_eq!(adapter.server_label(), "typescript-language-server");
        }
    }

    #[test]
    fn position_uses_lsp_utf16_units_and_rejects_missing_lines() {
        let source = "a😀b\nsecond";
        assert!(validate_utf16_position(source, 0, 4).is_ok());
        assert!(validate_utf16_position(source, 0, 2).is_err());
        assert!(validate_utf16_position(source, 0, 5).is_err());
        assert!(validate_utf16_position(source, 2, 0).is_err());
        assert!(validate_utf16_position("x\r\ny", 0, 1).is_ok());
        assert!(validate_utf16_position("x\r\ny", 0, 2).is_err());
    }
}
