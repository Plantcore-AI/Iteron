use super::{
    ActivationInput, ActivationMismatch, ActivationPathField, ActivationPathProblem,
    IMPLEMENTATION_ACTIVATION_SCHEMA_VERSION, ImplementationActivationDocument,
    ImplementationActivationError, ImplementationActivationIdentity, ImplementationSource,
    MAX_IMPLEMENTATION_ACTIVATION_SOURCES,
};
use crate::implementation::{
    ImplementationManifest, ImplementationRegistry, MAX_IMPLEMENTATION_CATALOG_BYTES,
    MAX_IMPLEMENTATION_ID_BYTES, MAX_IMPLEMENTATION_PATH_BYTES, ProcessLaunchPlan,
};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::ModuleId;
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

type ResolvedSources = (
    BTreeMap<ModuleId, ProcessLaunchPlan>,
    BTreeMap<ModuleId, ImplementationActivationIdentity>,
);

pub(super) fn validate_document(
    document: &ImplementationActivationDocument,
) -> Result<(), ImplementationActivationError> {
    if document.schema_version != IMPLEMENTATION_ACTIVATION_SCHEMA_VERSION {
        return Err(ImplementationActivationError::SchemaVersion {
            expected: IMPLEMENTATION_ACTIVATION_SCHEMA_VERSION,
            actual: document.schema_version,
        });
    }
    if !valid_prefixed_digest(&document.candidate_sha256) {
        return Err(ImplementationActivationError::InvalidCandidateDigest);
    }
    if document.sources.len() > MAX_IMPLEMENTATION_ACTIVATION_SOURCES {
        return Err(ImplementationActivationError::TooManySources {
            actual: document.sources.len(),
            max: MAX_IMPLEMENTATION_ACTIVATION_SOURCES,
        });
    }
    let mut modules = BTreeSet::new();
    let mut implementation_ids = BTreeSet::new();
    for (source_index, source) in document.sources.iter().enumerate() {
        if !modules.insert(source.module) {
            return Err(ImplementationActivationError::DuplicateModule);
        }
        if !implementation_ids.insert(source.implementation_id.as_str()) {
            return Err(ImplementationActivationError::DuplicateImplementation);
        }
        if !valid_implementation_id(&source.implementation_id) {
            return Err(ImplementationActivationError::InvalidSourceField {
                source_index,
                field: "implementation_id",
            });
        }
        for (field, digest) in [
            ("manifest_sha256", &source.manifest_sha256),
            ("artifact_sha256", &source.artifact_sha256),
        ] {
            if !valid_prefixed_digest(digest) {
                return Err(ImplementationActivationError::InvalidSourceField {
                    source_index,
                    field,
                });
            }
        }
    }
    Ok(())
}

pub(super) fn resolve(
    sources: Vec<ImplementationSource>,
    host_ceiling: CapabilitySet,
) -> Result<ResolvedSources, ImplementationActivationError> {
    let mut plans = BTreeMap::new();
    let mut identities = BTreeMap::new();
    for (source_index, source) in sources.into_iter().enumerate() {
        let catalog_path = checked_declared_path(
            &source.catalog_path,
            source_index,
            ActivationPathField::Catalog,
            ExpectedType::File,
        )?;
        let artifact_root = checked_declared_path(
            &source.artifact_root,
            source_index,
            ActivationPathField::ArtifactRoot,
            ExpectedType::Directory,
        )?;
        let catalog_bytes = read_catalog(&catalog_path, source_index)?;
        super::strict_value(&catalog_bytes, ActivationInput::Catalog)?;
        let registry =
            ImplementationRegistry::from_json(&catalog_bytes, host_ceiling).map_err(|error| {
                ImplementationActivationError::Registry {
                    source_index,
                    error,
                }
            })?;
        let admitted = registry.resolve(&source.implementation_id).ok_or(
            ImplementationActivationError::SourceMismatch {
                source_index,
                mismatch: ActivationMismatch::MissingImplementation,
            },
        )?;
        validate_selected_manifest(admitted.manifest.clone(), &source, source_index)?;
        let executable = artifact_root.join(&admitted.manifest.executable);
        checked_existing_path(
            &executable,
            source_index,
            ActivationPathField::Executable,
            ExpectedType::File,
        )?;
        let verified = registry
            .verify_artifact_path(&source.implementation_id, &executable)
            .map_err(|error| ImplementationActivationError::Registry {
                source_index,
                error,
            })?
            .ok_or(ImplementationActivationError::SourceMismatch {
                source_index,
                mismatch: ActivationMismatch::MissingImplementation,
            })?;
        let plan = registry
            .launch_plan(&source.implementation_id, &artifact_root, &verified)
            .map_err(|error| ImplementationActivationError::Registry {
                source_index,
                error,
            })?
            .ok_or(ImplementationActivationError::SourceMismatch {
                source_index,
                mismatch: ActivationMismatch::MissingPlan,
            })?;
        let module = source.module;
        let identity = ImplementationActivationIdentity {
            module,
            implementation_id: source.implementation_id,
            catalog_path,
            artifact_root,
            manifest_sha256: source.manifest_sha256,
            artifact_sha256: source.artifact_sha256,
        };
        plans.insert(module, plan);
        identities.insert(module, identity);
    }
    Ok((plans, identities))
}

fn validate_selected_manifest(
    manifest: ImplementationManifest,
    source: &ImplementationSource,
    source_index: usize,
) -> Result<(), ImplementationActivationError> {
    if manifest.module != source.module {
        return Err(ImplementationActivationError::SourceMismatch {
            source_index,
            mismatch: ActivationMismatch::Module,
        });
    }
    let bytes = serde_json::to_vec(&manifest)
        .map_err(|_| ImplementationActivationError::ManifestEncoding { source_index })?;
    if prefixed_sha256(&bytes) != source.manifest_sha256 {
        return Err(ImplementationActivationError::SourceMismatch {
            source_index,
            mismatch: ActivationMismatch::ManifestDigest,
        });
    }
    if format!("sha256:{}", manifest.artifact_sha256) != source.artifact_sha256 {
        return Err(ImplementationActivationError::SourceMismatch {
            source_index,
            mismatch: ActivationMismatch::ArtifactDeclaration,
        });
    }
    Ok(())
}

fn read_catalog(
    path: &Path,
    source_index: usize,
) -> Result<Vec<u8>, ImplementationActivationError> {
    let metadata = path
        .metadata()
        .map_err(|_| ImplementationActivationError::CatalogRead { source_index })?;
    let metadata_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if metadata_len > MAX_IMPLEMENTATION_CATALOG_BYTES {
        return Err(ImplementationActivationError::TooLarge {
            input: ActivationInput::Catalog,
            actual: metadata_len,
            max: MAX_IMPLEMENTATION_CATALOG_BYTES,
        });
    }
    let file = File::open(path)
        .map_err(|_| ImplementationActivationError::CatalogRead { source_index })?;
    let mut bytes = Vec::with_capacity(metadata_len);
    file.take((MAX_IMPLEMENTATION_CATALOG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ImplementationActivationError::CatalogRead { source_index })?;
    if bytes.len() > MAX_IMPLEMENTATION_CATALOG_BYTES {
        return Err(ImplementationActivationError::TooLarge {
            input: ActivationInput::Catalog,
            actual: bytes.len(),
            max: MAX_IMPLEMENTATION_CATALOG_BYTES,
        });
    }
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum ExpectedType {
    File,
    Directory,
}

fn checked_declared_path(
    value: &str,
    source_index: usize,
    field: ActivationPathField,
    expected: ExpectedType,
) -> Result<PathBuf, ImplementationActivationError> {
    if value.is_empty()
        || value.len() > MAX_IMPLEMENTATION_PATH_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(path_error(
            source_index,
            field,
            ActivationPathProblem::Invalid,
        ));
    }
    let path = PathBuf::from(value);
    checked_existing_path(&path, source_index, field, expected)?;
    Ok(path)
}

fn checked_existing_path(
    path: &Path,
    source_index: usize,
    field: ActivationPathField,
    expected: ExpectedType,
) -> Result<(), ImplementationActivationError> {
    if !path.is_absolute() {
        return Err(path_error(
            source_index,
            field,
            ActivationPathProblem::Relative,
        ));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| path_error(source_index, field, ActivationPathProblem::Missing))?;
    if metadata.file_type().is_symlink() {
        return Err(path_error(
            source_index,
            field,
            ActivationPathProblem::Symlink,
        ));
    }
    let correct_type = match expected {
        ExpectedType::File => metadata.is_file(),
        ExpectedType::Directory => metadata.is_dir(),
    };
    if !correct_type {
        return Err(path_error(
            source_index,
            field,
            ActivationPathProblem::WrongType,
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| path_error(source_index, field, ActivationPathProblem::Missing))?;
    if canonical != path {
        return Err(path_error(
            source_index,
            field,
            ActivationPathProblem::NonCanonical,
        ));
    }
    Ok(())
}

fn path_error(
    source_index: usize,
    field: ActivationPathField,
    problem: ActivationPathProblem,
) -> ImplementationActivationError {
    ImplementationActivationError::Path {
        source_index,
        field,
        problem,
    }
}

fn valid_implementation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IMPLEMENTATION_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_prefixed_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}
