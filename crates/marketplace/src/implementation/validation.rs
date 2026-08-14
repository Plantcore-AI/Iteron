use super::{
    IMPLEMENTATION_PROCESS_PROTOCOL_V1, IMPLEMENTATION_PROCESS_PROTOCOL_VERSION,
    ImplementationError, ImplementationManifest, MAX_IMPLEMENTATION_ARG_BYTES,
    MAX_IMPLEMENTATION_ARGV, MAX_IMPLEMENTATION_ARGV_BYTES, MAX_IMPLEMENTATION_CANCELLATION_MS,
    MAX_IMPLEMENTATION_DEPENDENCIES, MAX_IMPLEMENTATION_EVIDENCE_BYTES,
    MAX_IMPLEMENTATION_OBSERVATIONS, MAX_IMPLEMENTATION_PATH_BYTES, MAX_IMPLEMENTATION_RUNTIME_MS,
    valid_id,
};
use std::collections::BTreeSet;
use std::path::{Component, Path};

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_relative_executable(executable: &str) -> bool {
    if executable.is_empty()
        || executable.len() > MAX_IMPLEMENTATION_PATH_BYTES
        || executable.contains('\\')
        || executable.chars().any(char::is_control)
    {
        return false;
    }
    let path = Path::new(executable);
    !path.is_absolute()
        && path.components().all(|component| match component {
            Component::Normal(value) => value.to_str().is_some_and(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            }),
            _ => false,
        })
}

pub(super) fn validate_manifest(
    manifest: &ImplementationManifest,
) -> Result<(), ImplementationError> {
    let id = &manifest.implementation_id;
    if !valid_id(id) {
        return Err(ImplementationError::InvalidId(id.clone()));
    }
    if manifest.implementation_version == crate::Version::default() {
        return Err(ImplementationError::InvalidVersion(id.clone()));
    }
    if !valid_digest(&manifest.artifact_sha256) {
        return Err(ImplementationError::InvalidDigest {
            implementation: id.clone(),
            digest: manifest.artifact_sha256.clone(),
        });
    }
    if !valid_relative_executable(&manifest.executable) {
        return Err(ImplementationError::InvalidExecutable {
            implementation: id.clone(),
            path: manifest.executable.clone(),
        });
    }
    let argv_bytes = manifest.argv.iter().map(String::len).sum::<usize>();
    if manifest.argv.len() > MAX_IMPLEMENTATION_ARGV
        || argv_bytes > MAX_IMPLEMENTATION_ARGV_BYTES
        || manifest.argv.iter().any(|arg| {
            arg.len() > MAX_IMPLEMENTATION_ARG_BYTES || arg.chars().any(char::is_control)
        })
    {
        return Err(ImplementationError::InvalidArgv(id.clone()));
    }
    if !matches!(
        manifest.protocol_version,
        IMPLEMENTATION_PROCESS_PROTOCOL_V1 | IMPLEMENTATION_PROCESS_PROTOCOL_VERSION
    ) {
        return Err(ImplementationError::UnsupportedProtocol {
            implementation: id.clone(),
            expected: IMPLEMENTATION_PROCESS_PROTOCOL_VERSION,
            actual: manifest.protocol_version,
        });
    }
    let limits = &manifest.evidence_limits;
    if manifest.runtime_deadline_ms == 0
        || manifest.runtime_deadline_ms > MAX_IMPLEMENTATION_RUNTIME_MS
        || manifest.cancellation_deadline_ms == 0
        || manifest.cancellation_deadline_ms > MAX_IMPLEMENTATION_CANCELLATION_MS
        || limits.stdout_bytes == 0
        || limits.stdout_bytes > MAX_IMPLEMENTATION_EVIDENCE_BYTES
        || limits.stderr_bytes == 0
        || limits.stderr_bytes > MAX_IMPLEMENTATION_EVIDENCE_BYTES
        || limits.observations == 0
        || limits.observations > MAX_IMPLEMENTATION_OBSERVATIONS
    {
        return Err(ImplementationError::InvalidBounds(id.clone()));
    }
    if manifest.dependencies.len() > MAX_IMPLEMENTATION_DEPENDENCIES {
        return Err(ImplementationError::InvalidDependencies(id.clone()));
    }
    let mut dependencies = BTreeSet::new();
    for dependency in &manifest.dependencies {
        if !valid_id(&dependency.implementation_id)
            || dependency.implementation_id == *id
            || dependency.minimum_version == crate::Version::default()
            || !dependencies.insert(dependency.implementation_id.as_str())
        {
            return Err(ImplementationError::InvalidDependencies(id.clone()));
        }
    }
    Ok(())
}
