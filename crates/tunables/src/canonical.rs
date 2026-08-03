use crate::{
    CANONICALIZATION, DIGEST_ALGORITHM, Family, REGISTRY_ID, REGISTRY_REVISION,
    REGISTRY_SCHEMA_VERSION, families, validate_registry,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Digest input. It contains no maps, floats, optional fields, or self-referential digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalPayload<'a> {
    pub schema_version: u16,
    pub registry_id: &'static str,
    pub registry_revision: u16,
    pub canonicalization: &'static str,
    pub family_count: usize,
    pub families: &'a [Family],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalDigest {
    pub algorithm: &'static str,
    pub value: String,
}

/// Published machine artifact. `digest` authenticates `payload`'s exact canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalArtifact<'a> {
    pub digest: CanonicalDigest,
    pub payload: CanonicalPayload<'a>,
}

fn payload() -> CanonicalPayload<'static> {
    let families = families();
    CanonicalPayload {
        schema_version: REGISTRY_SCHEMA_VERSION,
        registry_id: REGISTRY_ID,
        registry_revision: REGISTRY_REVISION,
        canonicalization: CANONICALIZATION,
        family_count: families.len(),
        families,
    }
}

pub fn canonical_payload_json() -> Result<Vec<u8>, crate::RegistryError> {
    validate_registry()?;
    serde_json::to_vec(&payload()).map_err(crate::RegistryError::CanonicalEncoding)
}

pub fn registry_digest() -> Result<CanonicalDigest, crate::RegistryError> {
    let bytes = canonical_payload_json()?;
    Ok(CanonicalDigest {
        algorithm: DIGEST_ALGORITHM,
        value: hex::encode(Sha256::digest(bytes)),
    })
}

pub fn canonical_artifact() -> Result<CanonicalArtifact<'static>, crate::RegistryError> {
    Ok(CanonicalArtifact {
        digest: registry_digest()?,
        payload: payload(),
    })
}

pub fn canonical_artifact_json() -> Result<Vec<u8>, crate::RegistryError> {
    let mut bytes = serde_json::to_vec_pretty(&canonical_artifact()?)
        .map_err(crate::RegistryError::CanonicalEncoding)?;
    bytes.push(b'\n');
    Ok(bytes)
}
