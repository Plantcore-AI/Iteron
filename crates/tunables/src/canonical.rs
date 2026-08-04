use crate::{
    CANONICALIZATION, DIGEST_ALGORITHM, FAMILY_CANONICALIZATION, Family, REGISTRY_ID,
    REGISTRY_REVISION, REGISTRY_SCHEMA_VERSION, SCALAR_CATALOGS, ScalarCatalogDefinition, families,
    validate_registry,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Digest input for one semantic family. It deliberately excludes the digest itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct FamilySemanticPayload<'a> {
    canonicalization: &'static str,
    family: &'a Family,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalDigest {
    pub algorithm: &'static str,
    pub value: String,
}

/// One canonical entry with an independently verifiable semantic digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalFamily<'a> {
    pub semantic_digest: CanonicalDigest,
    #[serde(flatten)]
    pub family: &'a Family,
}

/// Registry digest input. Its typed fields and ordered vectors have one deterministic JSON
/// representation and contain no self-referential digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalPayload<'a> {
    pub schema_version: u16,
    pub registry_id: &'static str,
    pub registry_revision: u16,
    pub canonicalization: &'static str,
    pub family_count: usize,
    pub scalar_catalogs: &'a [ScalarCatalogDefinition],
    pub families: Vec<CanonicalFamily<'a>>,
}

/// Published machine artifact. `digest` authenticates `payload`'s exact canonical bytes; each
/// `CanonicalFamily::semantic_digest` independently authenticates one family's semantic payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalArtifact<'a> {
    pub digest: CanonicalDigest,
    pub payload: CanonicalPayload<'a>,
}

pub fn family_semantic_digest(family: &Family) -> Result<CanonicalDigest, crate::RegistryError> {
    let bytes = serde_json::to_vec(&FamilySemanticPayload {
        canonicalization: FAMILY_CANONICALIZATION,
        family,
    })
    .map_err(crate::RegistryError::CanonicalEncoding)?;
    Ok(CanonicalDigest {
        algorithm: DIGEST_ALGORITHM,
        value: hex::encode(Sha256::digest(bytes)),
    })
}

fn payload() -> Result<CanonicalPayload<'static>, crate::RegistryError> {
    let registry = families();
    let canonical_families = registry
        .iter()
        .map(|family| {
            Ok(CanonicalFamily {
                semantic_digest: family_semantic_digest(family)?,
                family,
            })
        })
        .collect::<Result<Vec<_>, crate::RegistryError>>()?;
    Ok(CanonicalPayload {
        schema_version: REGISTRY_SCHEMA_VERSION,
        registry_id: REGISTRY_ID,
        registry_revision: REGISTRY_REVISION,
        canonicalization: CANONICALIZATION,
        family_count: registry.len(),
        scalar_catalogs: SCALAR_CATALOGS,
        families: canonical_families,
    })
}

fn payload_digest(payload: &CanonicalPayload<'_>) -> Result<CanonicalDigest, crate::RegistryError> {
    let bytes = serde_json::to_vec(payload).map_err(crate::RegistryError::CanonicalEncoding)?;
    Ok(CanonicalDigest {
        algorithm: DIGEST_ALGORITHM,
        value: hex::encode(Sha256::digest(bytes)),
    })
}

pub(crate) fn registry_digest_unvalidated() -> Result<CanonicalDigest, crate::RegistryError> {
    payload_digest(&payload()?)
}

pub fn canonical_payload_json() -> Result<Vec<u8>, crate::RegistryError> {
    validate_registry()?;
    serde_json::to_vec(&payload()?).map_err(crate::RegistryError::CanonicalEncoding)
}

pub fn registry_digest() -> Result<CanonicalDigest, crate::RegistryError> {
    validate_registry()?;
    payload_digest(&payload()?)
}

pub fn canonical_artifact() -> Result<CanonicalArtifact<'static>, crate::RegistryError> {
    validate_registry()?;
    let payload = payload()?;
    let digest = payload_digest(&payload)?;
    Ok(CanonicalArtifact { digest, payload })
}

pub fn canonical_artifact_json() -> Result<Vec<u8>, crate::RegistryError> {
    let mut bytes = serde_json::to_vec_pretty(&canonical_artifact()?)
        .map_err(crate::RegistryError::CanonicalEncoding)?;
    bytes.push(b'\n');
    Ok(bytes)
}
