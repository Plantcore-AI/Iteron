//! Private overflow retention for MCP results before model exposure.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{MAX_RESPONSE_BYTES, McpError};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub const DEFAULT_MCP_VISIBLE_RESULT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MCP_SPILL_RESULT_BYTES: usize = MAX_RESPONSE_BYTES;
pub const MAX_MCP_SPILL_RESULT_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpSpillCleanup {
    ToolEnd,
    TurnEnd,
    RunEnd,
    SessionEnd,
}

impl McpSpillCleanup {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ToolEnd => "tool_end",
            Self::TurnEnd => "turn_end",
            Self::RunEnd => "run_end",
            Self::SessionEnd => "session_end",
        }
    }

    /// Whether a lifecycle boundary is at or beyond the configured maximum retention scope.
    ///
    /// Calling a later boundary is intentionally sufficient: if an owner missed `turn_end`
    /// because the process crashed, `run_end` and finally `session_end` still fail closed instead
    /// of retaining the private spill indefinitely.
    pub const fn reached_by(self, boundary: Self) -> bool {
        cleanup_rank(boundary) >= cleanup_rank(self)
    }
}

const fn cleanup_rank(cleanup: McpSpillCleanup) -> u8 {
    match cleanup {
        McpSpillCleanup::ToolEnd => 0,
        McpSpillCleanup::TurnEnd => 1,
        McpSpillCleanup::RunEnd => 2,
        McpSpillCleanup::SessionEnd => 3,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct McpResultPolicy {
    visible_max_bytes: usize,
    spill_max_bytes: usize,
    cleanup: McpSpillCleanup,
}

impl McpResultPolicy {
    pub fn new(
        visible_max_bytes: usize,
        spill_max_bytes: usize,
        cleanup: McpSpillCleanup,
    ) -> Result<Self, McpError> {
        if visible_max_bytes > spill_max_bytes || spill_max_bytes > MAX_MCP_SPILL_RESULT_BYTES {
            return Err(McpError::InvalidResultPolicy);
        }
        Ok(Self {
            visible_max_bytes,
            spill_max_bytes,
            cleanup,
        })
    }

    pub const fn visible_max_bytes(self) -> usize {
        self.visible_max_bytes
    }

    pub const fn spill_max_bytes(self) -> usize {
        self.spill_max_bytes
    }

    pub const fn cleanup(self) -> McpSpillCleanup {
        self.cleanup
    }
}

impl Default for McpResultPolicy {
    fn default() -> Self {
        Self::new(
            DEFAULT_MCP_VISIBLE_RESULT_BYTES,
            DEFAULT_MCP_SPILL_RESULT_BYTES,
            McpSpillCleanup::SessionEnd,
        )
        .expect("the built-in MCP result policy is valid")
    }
}

const SHA256_BYTES: usize = 32;
const MAX_TEMP_CREATE_ATTEMPTS: u64 = 64;

/// A bounded, content-addressed reference to one private spill.
///
/// The backing path stays private to [`McpSpillStore`]. The only value that may cross the model
/// boundary is this fixed-size store reference; it cannot be used to escape the store root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct McpSpillHandle([u8; SHA256_BYTES]);

impl McpSpillHandle {
    fn for_content(content: &[u8]) -> Self {
        Self(Sha256::digest(content).into())
    }

    fn file_name(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity("spill-".len() + (SHA256_BYTES * 2) + ".bin".len());
        name.push_str("spill-");
        for byte in self.0 {
            name.push(HEX[usize::from(byte >> 4)] as char);
            name.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        name.push_str(".bin");
        name
    }
}

impl fmt::Display for McpSpillHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub(crate) struct McpSpillStore {
    root: PathBuf,
    next_temporary: AtomicU64,
    files: Mutex<BTreeMap<McpSpillHandle, PathBuf>>,
}

impl McpSpillStore {
    pub(crate) fn create() -> Result<Self, McpError> {
        static STORE_SEQ: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        for _ in 0..64 {
            let sequence = STORE_SEQ.fetch_add(1, Ordering::SeqCst);
            let root = base.join(format!("iteron-mcp-spill-{}-{sequence}", std::process::id()));
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&root) {
                Ok(()) => {
                    if sync_directory(&base).is_err() {
                        let _ = std::fs::remove_dir(&root);
                        return Err(McpError::SpillStorageUnavailable);
                    }
                    return Ok(Self {
                        root,
                        next_temporary: AtomicU64::new(1),
                        files: Mutex::new(BTreeMap::new()),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(McpError::SpillStorageUnavailable),
            }
        }
        Err(McpError::SpillStorageUnavailable)
    }

    pub(crate) fn retain(&self, content: &[u8]) -> Result<McpSpillHandle, McpError> {
        let handle = McpSpillHandle::for_content(content);
        let mut files = self
            .files
            .lock()
            .map_err(|_| McpError::SpillStorageUnavailable)?;
        if files.contains_key(&handle) {
            return Ok(handle);
        }

        let path = self.root.join(handle.file_name());
        let (temporary_path, mut temporary) = self.create_temporary()?;
        let publish = (|| -> std::io::Result<()> {
            temporary.write_all(content)?;
            temporary.flush()?;
            temporary.sync_all()?;
            drop(temporary);

            // Linking a fully fsynced inode creates the final name atomically and never replaces
            // an existing entry. No reader can observe partial bytes. Removing the temporary name
            // and syncing the directory before returning makes the published entry durable.
            std::fs::hard_link(&temporary_path, &path)?;
            std::fs::remove_file(&temporary_path)?;
            sync_directory(&self.root)
        })();
        if publish.is_err() {
            let _ = std::fs::remove_file(&temporary_path);
            let _ = std::fs::remove_file(&path);
            let _ = sync_directory(&self.root);
            return Err(McpError::SpillStorageUnavailable);
        }

        files.insert(handle, path);
        Ok(handle)
    }

    /// Remove every retained spill once its configured lifecycle scope has ended.
    ///
    /// Successfully removed entries leave the index immediately. A failed removal remains
    /// indexed so a later, broader lifecycle boundary or `Drop` can retry it. No path or content
    /// is returned to the caller.
    pub(crate) fn cleanup(
        &self,
        configured: McpSpillCleanup,
        boundary: McpSpillCleanup,
    ) -> Result<(), McpError> {
        if !configured.reached_by(boundary) {
            return Ok(());
        }
        let mut files = self
            .files
            .lock()
            .map_err(|_| McpError::SpillStorageUnavailable)?;
        let handles = files.keys().copied().collect::<Vec<_>>();
        let mut failed = false;
        for handle in handles {
            let Some(path) = files.get(&handle) else {
                continue;
            };
            match std::fs::remove_file(path) {
                Ok(()) => {
                    files.remove(&handle);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    files.remove(&handle);
                }
                Err(_) => failed = true,
            }
        }
        if sync_directory(&self.root).is_err() {
            failed = true;
        }
        if failed {
            Err(McpError::SpillStorageUnavailable)
        } else {
            Ok(())
        }
    }

    fn create_temporary(&self) -> Result<(PathBuf, File), McpError> {
        let first = self
            .next_temporary
            .fetch_add(MAX_TEMP_CREATE_ATTEMPTS, Ordering::Relaxed);
        for offset in 0..MAX_TEMP_CREATE_ATTEMPTS {
            let path = self.root.join(format!(
                ".spill-{}-{}.tmp",
                std::process::id(),
                first.saturating_add(offset)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(McpError::SpillStorageUnavailable),
            }
        }
        Err(McpError::SpillStorageUnavailable)
    }

    #[cfg(test)]
    pub(crate) fn retained_count(&self) -> usize {
        self.files.lock().unwrap().len()
    }

    #[cfg(test)]
    fn retained_content(&self, handle: McpSpillHandle) -> Vec<u8> {
        let files = self.files.lock().unwrap();
        std::fs::read(files.get(&handle).unwrap()).unwrap()
    }

    #[cfg(test)]
    fn root(&self) -> PathBuf {
        self.root.clone()
    }
}

impl Drop for McpSpillStore {
    fn drop(&mut self) {
        let parent = self.root.parent().map(std::path::Path::to_path_buf);
        let files = self
            .files
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, path) in std::mem::take(files) {
            let _ = std::fs::remove_file(path);
        }
        if std::fs::remove_dir(&self.root).is_ok()
            && let Some(parent) = parent
        {
            let _ = sync_directory(&parent);
        }
    }
}

#[cfg(unix)]
fn sync_directory(path: &std::path::Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spill_handle_is_full_sha256_and_identical_content_is_deduplicated() {
        let store = McpSpillStore::create().unwrap();
        let first = store.retain(b"abc").unwrap();
        let second = store.retain(b"abc").unwrap();

        assert_eq!(first, second);
        assert_eq!(store.retained_count(), 1);
        assert_eq!(store.retained_content(first), b"abc");
        assert_eq!(
            first.to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(first.to_string().len(), "sha256:".len() + 64);
        assert!(std::fs::read_dir(store.root()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn dropping_store_removes_session_spills() {
        let store = McpSpillStore::create().unwrap();
        let root = store.root();
        store.retain(b"private result").unwrap();
        assert!(root.exists());

        drop(store);

        assert!(!root.exists());
    }

    #[test]
    fn configured_cleanup_waits_for_its_boundary_and_later_boundaries_fail_closed() {
        let store = McpSpillStore::create().unwrap();
        store.retain(b"private result").unwrap();

        store
            .cleanup(McpSpillCleanup::RunEnd, McpSpillCleanup::TurnEnd)
            .unwrap();
        assert_eq!(store.retained_count(), 1);

        store
            .cleanup(McpSpillCleanup::RunEnd, McpSpillCleanup::RunEnd)
            .unwrap();
        assert_eq!(store.retained_count(), 0);

        store.retain(b"second private result").unwrap();
        store
            .cleanup(McpSpillCleanup::ToolEnd, McpSpillCleanup::SessionEnd)
            .unwrap();
        assert_eq!(store.retained_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn spill_directory_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let store = McpSpillStore::create().unwrap();
        let handle = store.retain(b"private result").unwrap();
        let files = store.files.lock().unwrap();
        let path = files.get(&handle).unwrap();

        assert_eq!(
            std::fs::metadata(store.root())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
