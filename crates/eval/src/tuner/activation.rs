use super::{CandidateImplementation, TunerError};
use iteron_marketplace::{
    IMPLEMENTATION_ACTIVATION_SCHEMA_VERSION, ImplementationActivation,
    ImplementationActivationDocument, ImplementationSource, MAX_IMPLEMENTATION_ACTIVATION_BYTES,
};
use iteron_protocol::capability_set::CapabilitySet;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaterializedActivation {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub implementation_count: u64,
}

impl MaterializedActivation {
    pub(crate) fn verify(&self) -> Result<(), TunerError> {
        let path = Path::new(&self.path);
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| invalid("implementation activation is no longer readable"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != self.bytes
            || self.bytes > MAX_IMPLEMENTATION_ACTIVATION_BYTES as u64
        {
            return Err(invalid("implementation activation file identity changed"));
        }
        let mut bytes = Vec::with_capacity(self.bytes as usize);
        std::fs::File::open(path)
            .and_then(|file| {
                file.take((MAX_IMPLEMENTATION_ACTIVATION_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
            })
            .map_err(|_| invalid("implementation activation is no longer readable"))?;
        if bytes.len() as u64 != self.bytes {
            return Err(invalid("implementation activation byte count changed"));
        }
        if hex::encode(Sha256::digest(&bytes)) != self.sha256 {
            return Err(invalid("implementation activation digest changed"));
        }
        let activation = ImplementationActivation::from_json(&bytes, CapabilitySet::none())
            .map_err(|error| invalid(&format!("implementation activation rejected: {error}")))?;
        if activation.len() as u64 != self.implementation_count {
            return Err(invalid("implementation activation count changed"));
        }
        Ok(())
    }
}

pub(crate) fn materialize_activation(
    candidate_sha256: &str,
    implementations: &[CandidateImplementation],
    destination: &str,
) -> Result<MaterializedActivation, TunerError> {
    if implementations.is_empty() {
        return Err(invalid(
            "an empty candidate must not materialize an activation",
        ));
    }
    let document = ImplementationActivationDocument {
        schema_version: IMPLEMENTATION_ACTIVATION_SCHEMA_VERSION,
        candidate_sha256: candidate_sha256.to_owned(),
        sources: implementations
            .iter()
            .map(|implementation| ImplementationSource {
                module: implementation.module,
                implementation_id: implementation.implementation_id.clone(),
                catalog_path: implementation.catalog_path.clone(),
                artifact_root: implementation.artifact_root.clone(),
                manifest_sha256: implementation.manifest_sha256.clone(),
                artifact_sha256: implementation.artifact_sha256.clone(),
            })
            .collect(),
    };
    let encoded =
        serde_json::to_vec(&document).map_err(|error| TunerError::Encode(error.to_string()))?;
    if encoded.len() > MAX_IMPLEMENTATION_ACTIVATION_BYTES {
        return Err(invalid("implementation activation exceeds its byte bound"));
    }
    let activation = ImplementationActivation::from_json(&encoded, CapabilitySet::none())
        .map_err(|error| invalid(&format!("implementation activation rejected: {error}")))?;
    if activation.candidate_sha256() != candidate_sha256
        || activation.len() != implementations.len()
    {
        return Err(invalid("implementation activation identity mismatch"));
    }
    create_new_nofollow(Path::new(destination), &encoded)?;
    Ok(MaterializedActivation {
        path: destination.to_owned(),
        sha256: hex::encode(Sha256::digest(&encoded)),
        bytes: encoded.len() as u64,
        implementation_count: activation.len() as u64,
    })
}

fn create_new_nofollow(path: &Path, bytes: &[u8]) -> Result<(), TunerError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    if !path.is_absolute() || path.file_name().is_none() {
        return Err(invalid(
            "implementation activation destination is not absolute",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("implementation activation destination has no parent"))?;
    reject_symlink_components(parent)?;
    if parent
        .canonicalize()
        .map_err(|_| invalid("implementation activation parent is unavailable"))?
        != parent
    {
        return Err(invalid("implementation activation parent is not canonical"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_| invalid("implementation activation destination is not create-new"))?;
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(invalid(
            "implementation activation could not be written exactly",
        ));
    }
    let metadata = file
        .metadata()
        .map_err(|_| invalid("implementation activation metadata is unavailable"))?;
    if !metadata.is_file() || metadata.len() != bytes.len() as u64 {
        return Err(invalid(
            "implementation activation output is not a bounded regular file",
        ));
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), TunerError> {
    let mut prefix = std::path::PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        if matches!(component, std::path::Component::RootDir) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&prefix)
            .map_err(|_| invalid("implementation activation parent is unavailable"))?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("implementation activation path contains a symlink"));
        }
    }
    Ok(())
}

fn invalid(message: &str) -> TunerError {
    TunerError::InvalidSpec(message.into())
}
