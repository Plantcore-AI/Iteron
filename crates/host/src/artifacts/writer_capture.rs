//! Lazy internal writer scope. Unused publication factories do not walk both directory paths.
//!
//! Only immutable routing is cached; each publication still obtains the content owner's current
//! revocation/erasure checks. Public readers continue to verify recovered metadata through `open`.

use std::path::Path;
use std::sync::OnceLock;

use super::{ArtifactStoreError, DurableArtifactStore};

pub(crate) struct ArtifactWriterCapture {
    resolved: OnceLock<Result<DurableArtifactStore, ArtifactStoreError>>,
    #[cfg(unix)]
    scope: Result<unix::WriterScope, ArtifactStoreError>,
}

impl ArtifactWriterCapture {
    pub(crate) fn from_rollout_writer(rollout: &iteron_record::Rollout, workspace: &Path) -> Self {
        #[cfg(unix)]
        {
            Self {
                resolved: OnceLock::new(),
                scope: unix::WriterScope::capture(rollout, workspace),
            }
        }
        #[cfg(not(unix))]
        {
            // Keep eager validation where a portable stable directory identity is unavailable.
            Self {
                resolved: OnceLock::from(DurableArtifactStore::from_rollout_writer(
                    rollout, workspace,
                )),
            }
        }
    }

    pub(crate) fn get(&self) -> Result<&DurableArtifactStore, ArtifactStoreError> {
        #[cfg(unix)]
        let result = self
            .resolved
            .get_or_init(|| self.scope.as_ref().map_err(|error| *error)?.resolve());
        #[cfg(not(unix))]
        let result = self.resolved.get().ok_or(ArtifactStoreError::Scope)?;
        result.as_ref().map_err(|error| *error)
    }
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use iteron_protocol::{RunId, TenantId};
    use sha2::{Digest, Sha256};

    use super::{ArtifactStoreError, DurableArtifactStore};

    struct DirectoryCapture {
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    impl DirectoryCapture {
        fn capture(path: &Path) -> Result<Self, ArtifactStoreError> {
            // Resolve a relative path against the capture-time cwd without walking symlinks.
            let path = std::path::absolute(path).map_err(|_| ArtifactStoreError::Scope)?;
            let metadata = std::fs::metadata(&path).map_err(|_| ArtifactStoreError::Scope)?;
            if !metadata.is_dir() {
                return Err(ArtifactStoreError::Scope);
            }
            Ok(Self {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }

        fn resolve(&self) -> Result<PathBuf, ArtifactStoreError> {
            let path = self
                .path
                .canonicalize()
                .map_err(|_| ArtifactStoreError::Scope)?;
            let metadata = std::fs::metadata(&path).map_err(|_| ArtifactStoreError::Scope)?;
            // A renamed directory or redirected symlink must not grant a newly selected owner
            // authority merely because the factory did not publish until later.
            if !metadata.is_dir() || metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(ArtifactStoreError::Scope);
            }
            Ok(path)
        }
    }

    pub(super) struct WriterScope {
        runs: DirectoryCapture,
        workspace: DirectoryCapture,
        tenant: TenantId,
        run: RunId,
    }

    impl WriterScope {
        pub(super) fn capture(
            rollout: &iteron_record::Rollout,
            workspace: &Path,
        ) -> Result<Self, ArtifactStoreError> {
            Ok(Self {
                runs: DirectoryCapture::capture(
                    rollout.path().parent().ok_or(ArtifactStoreError::Scope)?,
                )?,
                workspace: DirectoryCapture::capture(workspace)?,
                tenant: rollout.tenant().clone(),
                run: rollout.run_id().clone(),
            })
        }

        pub(super) fn resolve(&self) -> Result<DurableArtifactStore, ArtifactStoreError> {
            let runs = self.runs.resolve()?;
            let workspace = self.workspace.resolve()?;
            Ok(DurableArtifactStore {
                workspace_digest: hex::encode(Sha256::digest(
                    workspace.to_string_lossy().as_bytes(),
                )),
                runs,
                tenant: self.tenant.clone(),
                run: self.run.clone(),
                workspace,
            })
        }
    }
}
