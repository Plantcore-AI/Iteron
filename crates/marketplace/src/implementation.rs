//! Runtime-loadable implementation manifests for public optimization seams.
//!
//! Admission validates identity, content address, dependency closure and resource bounds, then
//! intersects requested authority with a host ceiling. It does not activate, promote or execute an
//! implementation; those remain explicit host decisions outside this registry.

use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::ModuleId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

mod launch_plan;
mod validation;
pub use launch_plan::ProcessLaunchPlan;
use validation::validate_manifest;

pub const IMPLEMENTATION_CATALOG_SCHEMA_VERSION: u16 = 1;
pub const IMPLEMENTATION_PROCESS_PROTOCOL_VERSION: u16 = 1;
pub const MAX_IMPLEMENTATION_CATALOG_BYTES: usize = 512 * 1024;
pub const MAX_IMPLEMENTATIONS: usize = 256;
pub const MAX_IMPLEMENTATION_ID_BYTES: usize = 96;
pub const MAX_IMPLEMENTATION_PATH_BYTES: usize = 512;
pub const MAX_IMPLEMENTATION_ARGV: usize = 64;
pub const MAX_IMPLEMENTATION_ARG_BYTES: usize = 1024;
pub const MAX_IMPLEMENTATION_ARGV_BYTES: usize = 16 * 1024;
pub const MAX_IMPLEMENTATION_DEPENDENCIES: usize = 64;
pub const MAX_IMPLEMENTATION_RUNTIME_MS: u64 = 3_600_000;
pub const MAX_IMPLEMENTATION_CANCELLATION_MS: u64 = 300_000;
pub const MAX_IMPLEMENTATION_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_IMPLEMENTATION_OBSERVATIONS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationDependency {
    pub implementation_id: String,
    pub minimum_version: crate::Version,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLimits {
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub observations: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationFailurePolicy {
    FailClosed,
    RequestHostFallback,
    RequestHostQuarantine,
}

/// Public, content-addressed declaration for one external implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationManifest {
    pub implementation_id: String,
    pub implementation_version: crate::Version,
    pub module: ModuleId,
    pub artifact_sha256: String,
    /// Executable relative to the verified artifact root. Shell syntax is never accepted.
    pub executable: String,
    #[serde(default)]
    pub argv: Vec<String>,
    pub protocol_version: u16,
    #[serde(default)]
    pub requested_capabilities: CapabilitySet,
    #[serde(default)]
    pub dependencies: Vec<ImplementationDependency>,
    pub runtime_deadline_ms: u64,
    pub cancellation_deadline_ms: u64,
    pub evidence_limits: EvidenceLimits,
    pub failure_policy: ImplementationFailurePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationCatalog {
    pub schema_version: u16,
    pub implementations: Vec<ImplementationManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedImplementation {
    pub manifest: ImplementationManifest,
    /// Exact intersection of the manifest request and host ceiling; never a grant.
    pub admitted_capabilities: CapabilitySet,
}

/// Proof returned only after hashing artifact bytes. Its private field prevents a caller from
/// accidentally treating a manifest's claimed digest as observed content evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifactDigest(String);

impl VerifiedArtifactDigest {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImplementationError {
    #[error("implementation catalog is not valid bounded JSON: {0}")]
    MalformedJson(String),
    #[error("implementation catalog is {actual} bytes; maximum is {max}")]
    CatalogTooLarge { actual: usize, max: usize },
    #[error("implementation catalog schema version {actual} is not {expected}")]
    CatalogSchemaVersion { expected: u16, actual: u16 },
    #[error("implementation catalog has {actual} entries; maximum is {max}")]
    TooManyImplementations { actual: usize, max: usize },
    #[error("invalid implementation id {0:?}")]
    InvalidId(String),
    #[error("implementation {0} has an invalid zero version")]
    InvalidVersion(String),
    #[error("implementation {implementation} has invalid SHA-256 {digest:?}")]
    InvalidDigest {
        implementation: String,
        digest: String,
    },
    #[error("artifact digest is {actual}; expected {expected}")]
    ArtifactDigestMismatch { expected: String, actual: String },
    #[error("implementation {implementation} has unsafe executable path {path:?}")]
    InvalidExecutable {
        implementation: String,
        path: String,
    },
    #[error("implementation {0} has invalid or oversized argv")]
    InvalidArgv(String),
    #[error(
        "implementation {implementation} protocol {actual} is not supported version {expected}"
    )]
    UnsupportedProtocol {
        implementation: String,
        expected: u16,
        actual: u16,
    },
    #[error("implementation {0} has invalid resource or evidence bounds")]
    InvalidBounds(String),
    #[error("implementation {0} has invalid or duplicate dependency declarations")]
    InvalidDependencies(String),
    #[error("implementation {0} is declared more than once")]
    DuplicateImplementation(String),
    #[error("implementation {implementation} requires missing {dependency}")]
    MissingDependency {
        implementation: String,
        dependency: String,
    },
    #[error("implementation {implementation} requires {dependency}>={minimum}, found {actual}")]
    DependencyTooOld {
        implementation: String,
        dependency: String,
        minimum: crate::Version,
        actual: crate::Version,
    },
    #[error("implementation dependency graph contains a cycle")]
    DependencyCycle,
    #[error("artifact root must be an absolute UTF-8 path")]
    InvalidArtifactRoot,
    #[error("artifact path must be an absolute canonical regular non-symlink file")]
    InvalidArtifactPath,
    #[error("artifact could not be read for streaming verification")]
    ArtifactRead,
}

pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_IMPLEMENTATION_ID_BYTES
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone)]
pub struct ImplementationRegistry {
    host_ceiling: CapabilitySet,
    implementations: BTreeMap<String, AdmittedImplementation>,
}

impl ImplementationRegistry {
    #[must_use]
    pub fn new(host_ceiling: CapabilitySet) -> Self {
        Self {
            host_ceiling,
            implementations: BTreeMap::new(),
        }
    }

    pub fn from_json(
        bytes: &[u8],
        host_ceiling: CapabilitySet,
    ) -> Result<Self, ImplementationError> {
        if bytes.len() > MAX_IMPLEMENTATION_CATALOG_BYTES {
            return Err(ImplementationError::CatalogTooLarge {
                actual: bytes.len(),
                max: MAX_IMPLEMENTATION_CATALOG_BYTES,
            });
        }
        let catalog: ImplementationCatalog = serde_json::from_slice(bytes)
            .map_err(|error| ImplementationError::MalformedJson(error.to_string()))?;
        if catalog.schema_version != IMPLEMENTATION_CATALOG_SCHEMA_VERSION {
            return Err(ImplementationError::CatalogSchemaVersion {
                expected: IMPLEMENTATION_CATALOG_SCHEMA_VERSION,
                actual: catalog.schema_version,
            });
        }
        if catalog.implementations.len() > MAX_IMPLEMENTATIONS {
            return Err(ImplementationError::TooManyImplementations {
                actual: catalog.implementations.len(),
                max: MAX_IMPLEMENTATIONS,
            });
        }
        let mut registry = Self::new(host_ceiling);
        registry.register_batch(catalog.implementations)?;
        Ok(registry)
    }

    pub fn register(
        &mut self,
        manifest: ImplementationManifest,
    ) -> Result<&AdmittedImplementation, ImplementationError> {
        validate_manifest(&manifest)?;
        let id = manifest.implementation_id.clone();
        if self.implementations.contains_key(&id) {
            return Err(ImplementationError::DuplicateImplementation(id));
        }
        self.validate_resolved_dependencies(&manifest)?;
        let admitted = AdmittedImplementation {
            admitted_capabilities: manifest.requested_capabilities.intersect(self.host_ceiling),
            manifest,
        };
        self.implementations.insert(id.clone(), admitted);
        Ok(&self.implementations[&id])
    }

    fn register_batch(
        &mut self,
        manifests: Vec<ImplementationManifest>,
    ) -> Result<(), ImplementationError> {
        let mut pending = BTreeMap::new();
        for manifest in manifests {
            validate_manifest(&manifest)?;
            let id = manifest.implementation_id.clone();
            if self.implementations.contains_key(&id)
                || pending.insert(id.clone(), manifest).is_some()
            {
                return Err(ImplementationError::DuplicateImplementation(id));
            }
        }
        for manifest in pending.values() {
            for dependency in &manifest.dependencies {
                let version = pending
                    .get(&dependency.implementation_id)
                    .map(|item| item.implementation_version)
                    .or_else(|| {
                        self.implementations
                            .get(&dependency.implementation_id)
                            .map(|item| item.manifest.implementation_version)
                    })
                    .ok_or_else(|| ImplementationError::MissingDependency {
                        implementation: manifest.implementation_id.clone(),
                        dependency: dependency.implementation_id.clone(),
                    })?;
                if version < dependency.minimum_version {
                    return Err(ImplementationError::DependencyTooOld {
                        implementation: manifest.implementation_id.clone(),
                        dependency: dependency.implementation_id.clone(),
                        minimum: dependency.minimum_version,
                        actual: version,
                    });
                }
            }
        }
        while !pending.is_empty() {
            let ready = pending.iter().find_map(|(id, manifest)| {
                manifest
                    .dependencies
                    .iter()
                    .all(|dep| self.implementations.contains_key(&dep.implementation_id))
                    .then(|| id.clone())
            });
            let Some(id) = ready else {
                return Err(ImplementationError::DependencyCycle);
            };
            let manifest = pending.remove(&id).expect("ready id came from pending");
            self.register(manifest)?;
        }
        Ok(())
    }

    fn validate_resolved_dependencies(
        &self,
        manifest: &ImplementationManifest,
    ) -> Result<(), ImplementationError> {
        for dependency in &manifest.dependencies {
            let actual = self
                .implementations
                .get(&dependency.implementation_id)
                .ok_or_else(|| ImplementationError::MissingDependency {
                    implementation: manifest.implementation_id.clone(),
                    dependency: dependency.implementation_id.clone(),
                })?
                .manifest
                .implementation_version;
            if actual < dependency.minimum_version {
                return Err(ImplementationError::DependencyTooOld {
                    implementation: manifest.implementation_id.clone(),
                    dependency: dependency.implementation_id.clone(),
                    minimum: dependency.minimum_version,
                    actual,
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn resolve(&self, implementation_id: &str) -> Option<&AdmittedImplementation> {
        self.implementations.get(implementation_id)
    }

    pub fn resolve_for_module(
        &self,
        implementation_id: &str,
        module: ModuleId,
    ) -> Option<&AdmittedImplementation> {
        self.resolve(implementation_id)
            .filter(|implementation| implementation.manifest.module == module)
    }

    pub fn resolve_content(&self, artifact_sha256: &str) -> Vec<&AdmittedImplementation> {
        self.implementations
            .values()
            .filter(|item| item.manifest.artifact_sha256 == artifact_sha256)
            .collect()
    }

    pub fn verify_artifact(
        &self,
        implementation_id: &str,
        artifact_bytes: &[u8],
    ) -> Result<Option<VerifiedArtifactDigest>, ImplementationError> {
        use sha2::Digest as _;
        let Some(implementation) = self.resolve(implementation_id) else {
            return Ok(None);
        };
        let actual = hex::encode(sha2::Sha256::digest(artifact_bytes));
        if actual != implementation.manifest.artifact_sha256 {
            return Err(ImplementationError::ArtifactDigestMismatch {
                expected: implementation.manifest.artifact_sha256.clone(),
                actual,
            });
        }
        Ok(Some(VerifiedArtifactDigest(actual)))
    }

    /// Hash an artifact from a fixed-size buffer without loading the executable into memory.
    pub fn verify_artifact_path(
        &self,
        implementation_id: &str,
        artifact_path: &Path,
    ) -> Result<Option<VerifiedArtifactDigest>, ImplementationError> {
        use sha2::Digest as _;
        use std::io::Read as _;

        let Some(implementation) = self.resolve(implementation_id) else {
            return Ok(None);
        };
        let metadata = std::fs::symlink_metadata(artifact_path)
            .map_err(|_| ImplementationError::ArtifactRead)?;
        if !artifact_path.is_absolute()
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || artifact_path
                .canonicalize()
                .map_err(|_| ImplementationError::ArtifactRead)?
                != artifact_path
        {
            return Err(ImplementationError::InvalidArtifactPath);
        }
        let mut file =
            std::fs::File::open(artifact_path).map_err(|_| ImplementationError::ArtifactRead)?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| ImplementationError::ArtifactRead)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let actual = hex::encode(hasher.finalize());
        if actual != implementation.manifest.artifact_sha256 {
            return Err(ImplementationError::ArtifactDigestMismatch {
                expected: implementation.manifest.artifact_sha256.clone(),
                actual,
            });
        }
        Ok(Some(VerifiedArtifactDigest(actual)))
    }

    pub fn launch_plan(
        &self,
        implementation_id: &str,
        artifact_root: &Path,
        verified_artifact: &VerifiedArtifactDigest,
    ) -> Result<Option<ProcessLaunchPlan>, ImplementationError> {
        let Some(implementation) = self.resolve(implementation_id) else {
            return Ok(None);
        };
        if verified_artifact.0 != implementation.manifest.artifact_sha256 {
            return Err(ImplementationError::ArtifactDigestMismatch {
                expected: implementation.manifest.artifact_sha256.clone(),
                actual: verified_artifact.0.clone(),
            });
        }
        if !artifact_root.is_absolute() {
            return Err(ImplementationError::InvalidArtifactRoot);
        }
        let program = artifact_root.join(&implementation.manifest.executable);
        let program = program
            .to_str()
            .ok_or(ImplementationError::InvalidArtifactRoot)?
            .to_owned();
        Ok(Some(ProcessLaunchPlan::mint(
            implementation,
            verified_artifact.0.clone(),
            program,
        )))
    }
}
