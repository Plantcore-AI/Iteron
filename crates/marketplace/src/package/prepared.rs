//! Verified install candidates are opaque host receipts, never client paths or trust-key grants.
use super::{ArtifactRef, PackageError, PluginStore};
use std::path::{Path, PathBuf};

pub struct PreparedPluginInstall {
    root: PathBuf,
    source: PathBuf,
    plugin: String,
    artifact: ArtifactRef,
}
impl std::fmt::Debug for PreparedPluginInstall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedPluginInstall")
            .field("plugin", &self.plugin)
            .field("artifact", &self.artifact)
            .finish_non_exhaustive()
    }
}
impl PreparedPluginInstall {
    pub fn plugin(&self) -> &str {
        &self.plugin
    }
    pub fn artifact(&self) -> &ArtifactRef {
        &self.artifact
    }
}
impl PluginStore {
    /// Caller supplies the trusted operator path at bootstrap, not through a network/model command.
    pub fn prepare_install(
        &self,
        operator_path: &Path,
    ) -> Result<PreparedPluginInstall, PackageError> {
        let root = self.root.canonicalize()?;
        let source = operator_path.canonicalize()?;
        let verified = self.verify_source(&source)?;
        Ok(PreparedPluginInstall {
            root,
            source,
            plugin: verified.manifest.plugin,
            artifact: ArtifactRef {
                version: verified.manifest.version,
                digest: verified.digest,
                key_id: verified.key_id,
            },
        })
    }
    pub fn install_prepared(
        &self,
        receipt: &PreparedPluginInstall,
    ) -> Result<ArtifactRef, PackageError> {
        if self.root.canonicalize()? != receipt.root {
            return Err(PackageError::MalformedRegistry);
        }
        let verified = self.verify_source(&receipt.source)?;
        if verified.manifest.plugin != receipt.plugin
            || verified.manifest.version != receipt.artifact.version
            || verified.digest != receipt.artifact.digest
            || verified.key_id != receipt.artifact.key_id
        {
            return Err(PackageError::MalformedRegistry);
        }
        // The installer copies into its private staging directory and verifies the copied tree
        // against this exact digest before any registry commit; source races cannot substitute it.
        self.install_verified_prepared(&receipt.source, verified, &receipt.artifact)
    }
}
