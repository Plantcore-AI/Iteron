//! Private, bounded startup snapshot for previously verified agent definitions.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::{AgentCatalog, AgentCatalogRuntimeIdentity, AgentDef};

const SNAPSHOT_VERSION: u8 = 1;
const DEFAULT_MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
struct SnapshotHardLimits {
    max_bytes: usize,
}

/// Private-cache admission is a security/resource invariant. Profiles may tune the ordinary
/// default downward or upward within this audited ceiling, but cannot train the ceiling itself.
const SNAPSHOT_HARD_LIMITS: SnapshotHardLimits = SnapshotHardLimits {
    max_bytes: 8 * 1024 * 1024,
};
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotEnvelope {
    version: u8,
    identity: AgentCatalogRuntimeIdentity,
    defs: Vec<AgentDef>,
}

/// Immutable bootstrap material. Loading validates byte/file bounds, private permissions, every
/// definition, built-in identity, uniqueness, and the canonical execution digest. Discovery errors
/// and source paths are deliberately omitted from this content-bearing private cache.
#[derive(Debug, Clone)]
pub struct AgentCatalogSnapshot {
    catalog: AgentCatalog,
}

impl AgentCatalogSnapshot {
    /// Load one O(1)-file snapshot. `Ok(None)` means no prior verified snapshot is available; the
    /// caller should paint with its explicit bootstrap state and refresh physical discovery later.
    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_file() {
            return Err(invalid("agent catalog snapshot is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "agent catalog snapshot must not be group/world accessible",
                ));
            }
        }
        let max = max_snapshot_bytes();
        if metadata.len() > max as u64 {
            return Err(invalid("agent catalog snapshot exceeds its byte bound"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?
            .take((max + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max {
            return Err(invalid("agent catalog snapshot exceeds its byte bound"));
        }
        let envelope: SnapshotEnvelope = serde_json::from_slice(&bytes)
            .map_err(|error| invalid(format!("invalid agent catalog snapshot: {error}")))?;
        if envelope.version != SNAPSHOT_VERSION {
            return Err(invalid("unsupported agent catalog snapshot version"));
        }
        let catalog = AgentCatalog::from_snapshot_defs(envelope.defs)
            .map_err(|error| invalid(format!("invalid agent catalog snapshot: {error}")))?;
        let identity = catalog.runtime_identity();
        if identity != envelope.identity {
            return Err(invalid("agent catalog snapshot identity mismatch"));
        }
        Ok(Some(Self { catalog }))
    }

    /// Atomically store a structurally revalidated catalog with private file permissions.
    pub fn store(path: &Path, catalog: &AgentCatalog) -> io::Result<Self> {
        let verified = AgentCatalog::from_snapshot_defs(catalog.defs().to_vec())
            .map_err(|error| invalid(format!("agent catalog cannot be snapshotted: {error}")))?;
        let identity = verified.runtime_identity();
        let bytes = serde_json::to_vec(&SnapshotEnvelope {
            version: SNAPSHOT_VERSION,
            identity: identity.clone(),
            defs: verified.defs().to_vec(),
        })
        .map_err(|error| invalid(format!("agent catalog snapshot encoding failed: {error}")))?;
        if bytes.len() > max_snapshot_bytes() {
            return Err(invalid("agent catalog snapshot exceeds its byte bound"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| invalid("snapshot path has no parent"))?;
        std::fs::create_dir_all(parent)?;
        let temporary = temporary_path(path);
        let result: io::Result<()> = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            #[cfg(unix)]
            {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
        Ok(Self { catalog: verified })
    }

    pub fn into_catalog(self) -> AgentCatalog {
        self.catalog
    }
}

fn max_snapshot_bytes() -> usize {
    iteron_tunables::param_usize(
        "agents.snapshot.default_max_snapshot_bytes",
        DEFAULT_MAX_SNAPSHOT_BYTES,
    )
    .clamp(1, SNAPSHOT_HARD_LIMITS.max_bytes)
}

fn temporary_path(path: &Path) -> PathBuf {
    let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{}", std::process::id(), sequence));
    path.with_file_name(name)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_snapshot_round_trips_exact_identity() {
        let root = std::env::temp_dir().join(format!(
            "iteron-agent-snapshot-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let path = root.join("catalog.json");
        let expected = AgentCatalog::builtin_only();
        let stored = AgentCatalogSnapshot::store(&path, &expected).unwrap();
        let loaded = AgentCatalogSnapshot::load(&path).unwrap().unwrap();
        assert_eq!(
            stored.catalog.runtime_identity(),
            loaded.catalog.runtime_identity()
        );
        assert_eq!(loaded.catalog.defs().len(), expected.defs().len());
        std::fs::remove_dir_all(root).ok();
    }
}
