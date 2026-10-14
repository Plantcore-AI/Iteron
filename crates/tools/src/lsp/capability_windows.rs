//! Actual readonly Windows source custody. A timed-out observer cannot release the worker's
//! population slot or retained source handles while its finite disk operation is still running.
use super::LspToolError;
use iteron_support::durable_windows_state::{WindowsWorkspaceReader, WindowsWorkspaceSource};
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
const MAX_SOURCE_READS: usize = 16;
static READS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[derive(Debug)]
pub(super) struct SourceBinding {
    source: Arc<WindowsWorkspaceSource>,
}
fn admit() -> Result<OwnedSemaphorePermit, LspToolError> {
    READS
        .get_or_init(|| Arc::new(Semaphore::new(MAX_SOURCE_READS)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| LspToolError::SourceUnavailable)
}
impl SourceBinding {
    pub(super) async fn open(
        root: &Path,
        relative: &Path,
        markers: &[String],
        limit: usize,
        wait: Duration,
    ) -> Result<(Self, PathBuf, Vec<u8>), LspToolError> {
        if root.as_os_str().encode_wide().take(4097).count() > 4096
            || relative.as_os_str().encode_wide().take(4097).count() > 4096
            || markers.len() > 128
            || markers.iter().any(|marker| !marker_is_relative(marker))
        {
            return Err(LspToolError::InvalidPath);
        }
        let permit = admit()?;
        let root = root.to_owned();
        let relative = relative.to_owned();
        let markers = markers.to_vec();
        let work = tokio::task::spawn_blocking(move || {
            let _physical = permit;
            let reader = WindowsWorkspaceReader::open(&root)
                .map_err(|_| LspToolError::WorkspaceUnavailable)?;
            let source = reader
                .bind_source(&relative)
                .map_err(|_| LspToolError::SourceUnavailable)?;
            // Namespace pins are already held. URI/marker lookup runs in the same physical
            // worker and keeps its population permit until the actual disk calls complete.
            let canonical_root = root
                .canonicalize()
                .map_err(|_| LspToolError::WorkspaceUnavailable)?;
            if !markers.is_empty() && !markers.iter().any(|marker| marker_visible(&reader, marker))
            {
                return Err(LspToolError::RouteWorkspaceMismatch);
            }
            if source.byte_len() > limit as u64 {
                return Err(LspToolError::SourceTooLarge { limit });
            }
            let bytes = source
                .read_bounded(limit)
                .map_err(|_| LspToolError::SourceUnavailable)?;
            Ok((
                Self {
                    source: Arc::new(source),
                },
                canonical_root,
                bytes,
            ))
        });
        tokio::time::timeout(wait, work)
            .await
            .map_err(|_| LspToolError::SourceUnavailable)?
            .map_err(|_| LspToolError::SourceUnavailable)?
    }
    pub(super) fn workspace(&self) -> &File {
        self.source.workspace()
    }
    pub(super) async fn read(
        &self,
        requested_root: &Path,
        canonical_root: &Path,
        limit: usize,
        wait: Duration,
    ) -> Result<Vec<u8>, LspToolError> {
        if requested_root.as_os_str().encode_wide().take(4097).count() > 4096
            || canonical_root.as_os_str().encode_wide().take(32768).count() > 32767
        {
            return Err(LspToolError::SourceChanged);
        }
        let permit = admit()?;
        let source = self.source.clone();
        let requested_root = requested_root.to_owned();
        let canonical_root = canonical_root.to_owned();
        let work = tokio::task::spawn_blocking(move || {
            let _physical = permit;
            if requested_root.canonicalize().ok().as_deref() != Some(canonical_root.as_path()) {
                return Err(LspToolError::SourceChanged);
            }
            source
                .read_bounded(limit)
                .map_err(|_| LspToolError::SourceChanged)
        });
        tokio::time::timeout(wait, work)
            .await
            .map_err(|_| LspToolError::SourceChanged)?
            .map_err(|_| LspToolError::SourceChanged)?
    }
}

fn marker_is_relative(marker: &str) -> bool {
    !marker.is_empty()
        && marker.len() <= 4096
        && !marker.chars().any(char::is_control)
        && Path::new(marker).components().count() <= 64
        && Path::new(marker)
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

fn marker_visible(root: &WindowsWorkspaceReader, marker: &str) -> bool {
    // Marker presence selects an already configured route; it never follows a reparse point to
    // inspect an outside object. Both ordinary files and ordinary directories are supported.
    if root.bind_source(Path::new(marker)).is_ok() {
        return true;
    }
    let mut current = None;
    for part in Path::new(marker).components() {
        if part == Component::CurDir {
            continue;
        }
        let Component::Normal(name) = part else {
            return false;
        };
        let Some(name) = name.to_str() else {
            return false;
        };
        let parent = current.as_ref().unwrap_or(root);
        let Ok(Some(child)) = parent.open_child(name) else {
            return false;
        };
        current = Some(child);
    }
    true
}
