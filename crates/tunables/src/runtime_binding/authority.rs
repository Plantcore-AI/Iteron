use super::RuntimeResolutionError;
use crate::ExternalCeiling;
use std::collections::BTreeMap;

/// Authenticated non-route authority identities captured by the trusted composition root. The
/// builder cannot mint these digests from the values it is about to consume.
#[derive(Debug, Clone)]
pub struct RuntimeAuthoritySet {
    pub(super) operator_digest_sha256: String,
    ceiling_digests: BTreeMap<ExternalCeiling, String>,
}

impl RuntimeAuthoritySet {
    pub fn new(operator_digest_sha256: impl Into<String>) -> Result<Self, RuntimeResolutionError> {
        let operator_digest_sha256 = operator_digest_sha256.into();
        validate_digest("operator_authority", &operator_digest_sha256)?;
        Ok(Self {
            operator_digest_sha256,
            ceiling_digests: BTreeMap::new(),
        })
    }

    pub fn bind_ceiling(
        mut self,
        ceiling: ExternalCeiling,
        digest_sha256: impl Into<String>,
    ) -> Result<Self, RuntimeResolutionError> {
        if matches!(
            ceiling,
            ExternalCeiling::OperatorAuthority
                | ExternalCeiling::ProviderCapability
                | ExternalCeiling::ContextWindow
        ) {
            return Err(RuntimeResolutionError::InvalidAuthorityDigest(format!(
                "{ceiling:?} has a dedicated authority owner"
            )));
        }
        let digest_sha256 = digest_sha256.into();
        validate_digest("constraint_authority", &digest_sha256)?;
        self.ceiling_digests.insert(ceiling, digest_sha256);
        Ok(self)
    }

    pub(super) fn digest_for(
        &self,
        ceiling: ExternalCeiling,
        route_attestation: &str,
    ) -> Result<String, RuntimeResolutionError> {
        match ceiling {
            ExternalCeiling::OperatorAuthority => Ok(self.operator_digest_sha256.clone()),
            ExternalCeiling::ProviderCapability | ExternalCeiling::ContextWindow => {
                Ok(route_attestation.to_owned())
            }
            other => self
                .ceiling_digests
                .get(&other)
                .cloned()
                .ok_or(RuntimeResolutionError::MissingConstraintAuthority(other)),
        }
    }
}

pub(super) fn validate_digest(label: &str, digest: &str) -> Result<(), RuntimeResolutionError> {
    let valid = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(RuntimeResolutionError::InvalidAuthorityDigest(
            label.to_owned(),
        ))
    }
}
