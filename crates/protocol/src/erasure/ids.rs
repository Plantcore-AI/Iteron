use super::ErasureValidationError;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_ERASURE_OPERATION_ID_BYTES: usize = 96;
pub const MAX_ERASURE_AUTHORITY_ID_BYTES: usize = 96;
pub const MAX_ERASURE_SCOPE_ID_BYTES: usize = 96;
pub const MAX_ERASURE_TARGET_ID_BYTES: usize = 200;
const SHA256_HEX_BYTES: usize = 64;

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

pub(super) fn valid_session_target(value: &str) -> bool {
    if !valid_identifier(value, MAX_ERASURE_TARGET_ID_BYTES) || value.ends_with('.') {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !stem
            .strip_prefix("COM")
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
        && !stem
            .strip_prefix("LPT")
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ErasureOperationId(String);

impl ErasureOperationId {
    pub fn new(value: impl Into<String>) -> Result<Self, ErasureValidationError> {
        let value = value.into();
        if !valid_identifier(&value, MAX_ERASURE_OPERATION_ID_BYTES) {
            return Err(ErasureValidationError::OperationId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ErasureOperationId {
    type Error = ErasureValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ErasureOperationId> for String {
    fn from(value: ErasureOperationId) -> Self {
        value.0
    }
}

impl fmt::Display for ErasureOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ErasureAuthorityId(String);

impl ErasureAuthorityId {
    pub fn new(value: impl Into<String>) -> Result<Self, ErasureValidationError> {
        let value = value.into();
        if !valid_identifier(&value, MAX_ERASURE_AUTHORITY_ID_BYTES) {
            return Err(ErasureValidationError::AuthorityId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ErasureAuthorityId {
    type Error = ErasureValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ErasureAuthorityId> for String {
    fn from(value: ErasureAuthorityId) -> Self {
        value.0
    }
}

impl fmt::Display for ErasureAuthorityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ErasureScopeId(String);

impl ErasureScopeId {
    pub fn new(value: impl Into<String>) -> Result<Self, ErasureValidationError> {
        let value = value.into();
        if !valid_identifier(&value, MAX_ERASURE_SCOPE_ID_BYTES) {
            return Err(ErasureValidationError::ScopeId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ErasureScopeId {
    type Error = ErasureValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ErasureScopeId> for String {
    fn from(value: ErasureScopeId) -> Self {
        value.0
    }
}

impl fmt::Display for ErasureScopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ErasureTargetId(String);

impl ErasureTargetId {
    pub fn new(value: impl Into<String>) -> Result<Self, ErasureValidationError> {
        let value = value.into();
        if !valid_identifier(&value, MAX_ERASURE_TARGET_ID_BYTES) {
            return Err(ErasureValidationError::TargetId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ErasureTargetId {
    type Error = ErasureValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ErasureTargetId> for String {
    fn from(value: ErasureTargetId) -> Self {
        value.0
    }
}

impl fmt::Display for ErasureTargetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A content address rather than content or an operator-supplied label.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ErasureContentDigest(String);

impl ErasureContentDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, ErasureValidationError> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(ErasureValidationError::ContentDigest);
        };
        if hex.len() != SHA256_HEX_BYTES
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ErasureValidationError::ContentDigest);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ErasureContentDigest {
    type Error = ErasureValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ErasureContentDigest> for String {
    fn from(value: ErasureContentDigest) -> Self {
        value.0
    }
}

impl fmt::Display for ErasureContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
