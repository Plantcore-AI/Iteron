//! Strict external activation document for verified process implementations.
//!
//! Activation resolves declared sources into registry-minted launch plans. It performs no spawn,
//! lifecycle operation, activation policy decision, or authority grant.

mod source;
mod strict_json;

use crate::implementation::{ImplementationError, ProcessLaunchPlan};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::ModuleId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const IMPLEMENTATION_ACTIVATION_SCHEMA_VERSION: u16 = 1;
pub const MAX_IMPLEMENTATION_ACTIVATION_BYTES: usize = 128 * 1024;
pub const MAX_IMPLEMENTATION_ACTIVATION_SOURCES: usize = ModuleId::ALL.len();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationActivationDocument {
    pub schema_version: u16,
    pub candidate_sha256: String,
    pub sources: Vec<ImplementationSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationSource {
    pub module: ModuleId,
    pub implementation_id: String,
    pub catalog_path: String,
    pub artifact_root: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
}

/// Verified source identity retained after the external document and catalog are closed.
/// Fields are private so callers cannot manufacture a receipt from an unverified second parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImplementationActivationIdentity {
    module: ModuleId,
    implementation_id: String,
    catalog_path: PathBuf,
    artifact_root: PathBuf,
    manifest_sha256: String,
    artifact_sha256: String,
}

impl ImplementationActivationIdentity {
    #[must_use]
    pub fn module(&self) -> ModuleId {
        self.module
    }

    #[must_use]
    pub fn implementation_id(&self) -> &str {
        &self.implementation_id
    }

    #[must_use]
    pub fn catalog_path(&self) -> &Path {
        &self.catalog_path
    }

    #[must_use]
    pub fn artifact_root(&self) -> &Path {
        &self.artifact_root
    }

    #[must_use]
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationInput {
    Document,
    Catalog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationPathField {
    Catalog,
    ArtifactRoot,
    Executable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationPathProblem {
    Invalid,
    Relative,
    Missing,
    Symlink,
    WrongType,
    NonCanonical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationMismatch {
    MissingImplementation,
    Module,
    ManifestDigest,
    ArtifactDeclaration,
    MissingPlan,
}

#[derive(Debug, thiserror::Error)]
pub enum ImplementationActivationError {
    #[error("implementation activation {input:?} JSON is malformed")]
    MalformedJson { input: ActivationInput },
    #[error("implementation activation {input:?} JSON contains a duplicate object key")]
    DuplicateJsonKey { input: ActivationInput },
    #[error("implementation activation {input:?} is {actual} bytes; maximum is {max}")]
    TooLarge {
        input: ActivationInput,
        actual: usize,
        max: usize,
    },
    #[error("implementation activation schema version {actual} is not {expected}")]
    SchemaVersion { expected: u16, actual: u16 },
    #[error("implementation activation candidate SHA-256 is invalid")]
    InvalidCandidateDigest,
    #[error("implementation activation has {actual} sources; maximum is {max}")]
    TooManySources { actual: usize, max: usize },
    #[error("implementation activation source {source_index} has an invalid field: {field}")]
    InvalidSourceField {
        source_index: usize,
        field: &'static str,
    },
    #[error("implementation activation repeats a module")]
    DuplicateModule,
    #[error("implementation activation repeats an implementation id")]
    DuplicateImplementation,
    #[error(
        "implementation activation source {source_index} {field:?} path is invalid: {problem:?}"
    )]
    Path {
        source_index: usize,
        field: ActivationPathField,
        problem: ActivationPathProblem,
    },
    #[error("implementation activation source {source_index} catalog could not be read")]
    CatalogRead { source_index: usize },
    #[error("implementation activation source {source_index} catalog was rejected")]
    Registry {
        source_index: usize,
        #[source]
        error: ImplementationError,
    },
    #[error(
        "implementation activation source {source_index} canonical manifest could not be encoded"
    )]
    ManifestEncoding { source_index: usize },
    #[error("implementation activation source {source_index} does not match: {mismatch:?}")]
    SourceMismatch {
        source_index: usize,
        mismatch: ActivationMismatch,
    },
}

/// Fully verified plans, ordered by [`ModuleId`]. No process has been started.
pub struct ImplementationActivation {
    candidate_sha256: String,
    plans: BTreeMap<ModuleId, ProcessLaunchPlan>,
    identities: BTreeMap<ModuleId, ImplementationActivationIdentity>,
}

impl ImplementationActivation {
    pub fn from_json(
        bytes: &[u8],
        host_ceiling: CapabilitySet,
    ) -> Result<Self, ImplementationActivationError> {
        if bytes.len() > MAX_IMPLEMENTATION_ACTIVATION_BYTES {
            return Err(ImplementationActivationError::TooLarge {
                input: ActivationInput::Document,
                actual: bytes.len(),
                max: MAX_IMPLEMENTATION_ACTIVATION_BYTES,
            });
        }
        let value = strict_value(bytes, ActivationInput::Document)?;
        let document: ImplementationActivationDocument =
            serde_json::from_value(value).map_err(|_| {
                ImplementationActivationError::MalformedJson {
                    input: ActivationInput::Document,
                }
            })?;
        source::validate_document(&document)?;
        let (plans, identities) = source::resolve(document.sources, host_ceiling)?;
        Ok(Self {
            candidate_sha256: document.candidate_sha256,
            plans,
            identities,
        })
    }

    #[must_use]
    pub fn candidate_sha256(&self) -> &str {
        &self.candidate_sha256
    }

    #[must_use]
    pub fn plan(&self, module: ModuleId) -> Option<&ProcessLaunchPlan> {
        self.plans.get(&module)
    }

    #[must_use]
    pub fn identity(&self, module: ModuleId) -> Option<&ImplementationActivationIdentity> {
        self.identities.get(&module)
    }

    #[must_use]
    pub fn manifest_sha256(&self, module: ModuleId) -> Option<&str> {
        self.identity(module)
            .map(ImplementationActivationIdentity::manifest_sha256)
    }

    pub fn identities(
        &self,
    ) -> impl ExactSizeIterator<Item = &ImplementationActivationIdentity> + DoubleEndedIterator + '_
    {
        self.identities.values()
    }

    pub fn plans(
        &self,
    ) -> impl ExactSizeIterator<Item = (ModuleId, &ProcessLaunchPlan)> + DoubleEndedIterator + '_
    {
        self.plans.iter().map(|(module, plan)| (*module, plan))
    }

    pub fn take_plan(&mut self, module: ModuleId) -> Option<ProcessLaunchPlan> {
        self.plans.remove(&module)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.plans.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plans.is_empty()
    }
}

fn strict_value(
    bytes: &[u8],
    input: ActivationInput,
) -> Result<serde_json::Value, ImplementationActivationError> {
    strict_json::parse(bytes).map_err(|error| match error {
        strict_json::StrictJsonError::DuplicateKey => {
            ImplementationActivationError::DuplicateJsonKey { input }
        }
        strict_json::StrictJsonError::Malformed => {
            ImplementationActivationError::MalformedJson { input }
        }
    })
}
