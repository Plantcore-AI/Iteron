//! Private manifest publication and cross-process serialization. No content bytes live here.

use std::fs;
#[cfg(not(windows))]
use std::fs::{File, OpenOptions};
#[cfg(not(windows))]
use std::io::Read;
use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use super::{ArtifactStoreError, DurableArtifactStore, Manifest};

const MAX_MANIFEST_BYTES: usize = 256 * 1024;

fn owner_key(
    tenant: &iteron_protocol::TenantId,
    run: &iteron_protocol::RunId,
) -> Result<String, ArtifactStoreError> {
    let identity = serde_json::to_vec(&(tenant, run)).map_err(|_| ArtifactStoreError::Corrupt)?;
    Ok(hex::encode(Sha256::digest(identity)))
}

pub(super) fn remove_catalog(
    runs: &Path,
    tenant: &iteron_protocol::TenantId,
    run: &iteron_protocol::RunId,
) -> Result<(), ArtifactStoreError> {
    let root = runs.join(".public-artifacts");
    if !directory(&root, false)? {
        return Ok(());
    }
    let owner = root.join(owner_key(tenant, run)?);
    if !directory(&owner, false)? {
        return Ok(());
    }
    // Content refs have already been erased and verified. These files contain only handles and
    // bounded metadata; removing one exact private owner directory never traverses a wire path.
    fs::remove_dir_all(owner).map_err(|_| ArtifactStoreError::Unavailable)?;
    #[cfg(unix)]
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ArtifactStoreError::Unavailable)?;
    Ok(())
}

pub(super) struct ManifestFile {
    #[cfg(not(windows))]
    path: PathBuf,
    #[cfg(not(windows))]
    _lock: File,
    #[cfg(windows)]
    snapshot: std::sync::Mutex<iteron_support::durable_windows_state::WindowsSnapshotStore>,
}

impl ManifestFile {
    pub(super) fn acquire(
        store: &DurableArtifactStore,
        create: bool,
    ) -> Result<Option<Self>, ArtifactStoreError> {
        let root = store.runs.join(".public-artifacts");
        if !directory(&root, create)? {
            return Ok(None);
        }
        let owner = owner_key(&store.tenant, &store.run)?;
        let directory_path = root.join(owner);
        if !directory(&directory_path, create)? {
            return Ok(None);
        }
        let path = directory_path.join("manifest.json");
        if !create && !path.exists() {
            return Ok(None);
        }
        #[cfg(windows)]
        {
            let snapshot = iteron_support::durable_windows_state::WindowsSnapshotStore::open(
                &directory_path,
                "manifest",
            )
            .map_err(|_| ArtifactStoreError::Unavailable)?;
            Ok(Some(Self {
                snapshot: std::sync::Mutex::new(snapshot),
            }))
        }
        #[cfg(not(windows))]
        {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create(create)
                .truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let lock = options
                .open(directory_path.join("owner.lock"))
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            if !lock
                .metadata()
                .map_err(|_| ArtifactStoreError::Unavailable)?
                .is_file()
            {
                return Err(ArtifactStoreError::Corrupt);
            }
            lock.try_lock()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            Ok(Some(Self { path, _lock: lock }))
        }
    }

    pub(super) fn read(&self) -> Result<Option<Manifest>, ArtifactStoreError> {
        #[cfg(windows)]
        {
            let bytes = self
                .snapshot
                .lock()
                .map_err(|_| ArtifactStoreError::Unavailable)?
                .load()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            bytes
                .map(|bytes| {
                    if bytes.len() > MAX_MANIFEST_BYTES {
                        return Err(ArtifactStoreError::Corrupt);
                    }
                    serde_json::from_slice(&bytes).map_err(|_| ArtifactStoreError::Corrupt)
                })
                .transpose()
        }
        #[cfg(not(windows))]
        {
            let metadata = match fs::symlink_metadata(&self.path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(ArtifactStoreError::Unavailable),
            };
            if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES as u64 {
                return Err(ArtifactStoreError::Corrupt);
            }
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let mut bytes = Vec::new();
            options
                .open(&self.path)
                .map_err(|_| ArtifactStoreError::Unavailable)?
                .take(MAX_MANIFEST_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            if bytes.len() > MAX_MANIFEST_BYTES {
                return Err(ArtifactStoreError::Corrupt);
            }
            serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| ArtifactStoreError::Corrupt)
        }
    }

    pub(super) fn write(&self, manifest: &Manifest) -> Result<(), ArtifactStoreError> {
        let bytes = serde_json::to_vec(manifest).map_err(|_| ArtifactStoreError::Corrupt)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ArtifactStoreError::Capacity);
        }
        #[cfg(windows)]
        {
            let mut snapshot = self
                .snapshot
                .lock()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            let first = snapshot
                .load()
                .map_err(|_| ArtifactStoreError::Unavailable)?
                .is_none();
            snapshot
                .publish(&bytes, first)
                .map_err(|_| ArtifactStoreError::PublicationUnknown)?;
        }
        #[cfg(not(windows))]
        {
            if let Ok(metadata) = fs::symlink_metadata(&self.path)
                && !metadata.is_file()
            {
                return Err(ArtifactStoreError::Corrupt);
            }
            crate::config::write_private_atomic(&self.path, &bytes)
                .map_err(|_| ArtifactStoreError::PublicationUnknown)?;
            #[cfg(unix)]
            File::open(self.path.parent().ok_or(ArtifactStoreError::Corrupt)?)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| ArtifactStoreError::PublicationUnknown)?;
        }
        Ok(())
    }
}

fn directory(path: &Path, create: bool) -> Result<bool, ArtifactStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(ArtifactStoreError::Corrupt),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(windows)]
            {
                iteron_support::durable_windows_state::provision_private_directory(path)
                    .map_err(|_| ArtifactStoreError::Unavailable)?;
            }
            #[cfg(not(windows))]
            {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder
                    .create(path)
                    .map_err(|_| ArtifactStoreError::Unavailable)?;
            }
            #[cfg(unix)]
            File::open(path.parent().ok_or(ArtifactStoreError::Corrupt)?)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            Ok(true)
        }
        Err(_) => Err(ArtifactStoreError::Unavailable),
    }
}
