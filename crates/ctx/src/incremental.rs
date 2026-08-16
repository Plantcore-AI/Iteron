//! Rebuildable incremental views for hot context resources.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const DEFAULT_MAX_INDEXED_FILE_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedResource {
    pub(crate) bytes: u64,
    pub(crate) modified_unix_nanos: u128,
    pub(crate) sha256: [u8; 32],
}

/// mtime/size-gated content-hash index. Unchanged resources require metadata only; changed files
/// are read once under a hard byte ceiling. The index is rebuildable and carries no authority.
#[derive(Debug, Default)]
pub(crate) struct ResourceMetadataIndex {
    entries: RwLock<BTreeMap<PathBuf, IndexedResource>>,
    revision: AtomicU64,
}

impl ResourceMetadataIndex {
    /// Refresh one hot-path resource without evicting unrelated entries. Missing/non-file paths
    /// remove their prior cache row and return `None`; unchanged files require metadata only.
    pub(crate) fn refresh_one(&self, path: &Path) -> std::io::Result<Option<IndexedResource>> {
        let mut entries = write(&self.entries);
        let before = entries.get(path).cloned();
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => {
                entries.remove(path);
                if before.is_some() {
                    self.revision.fetch_add(1, Ordering::AcqRel);
                }
                return Ok(None);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                entries.remove(path);
                if before.is_some() {
                    self.revision.fetch_add(1, Ordering::AcqRel);
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let modified_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_nanos());
        let bytes = metadata.len();
        if let Some(entry) = entries.get(path)
            && entry.bytes == bytes
            && entry.modified_unix_nanos == modified_unix_nanos
        {
            return Ok(Some(entry.clone()));
        }
        let limit = iteron_tunables::param_usize(
            "ctx.incremental.default_max_indexed_file_bytes",
            DEFAULT_MAX_INDEXED_FILE_BYTES,
        );
        if bytes > limit as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "indexed resource exceeds its byte bound",
            ));
        }
        let content = std::fs::read(path)?;
        if content.len() > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "indexed resource grew past its byte bound",
            ));
        }
        let entry = IndexedResource {
            bytes,
            modified_unix_nanos,
            sha256: Sha256::digest(content).into(),
        };
        entries.insert(path.to_path_buf(), entry.clone());
        if before.as_ref() != Some(&entry) {
            self.revision.fetch_add(1, Ordering::AcqRel);
        }
        Ok(Some(entry))
    }
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
