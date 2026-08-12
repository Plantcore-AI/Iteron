//! Load, validate and emit a tunables profile document.
//!
//! The resolver has always accepted a digest-pinned [`crate::ResolutionProfile`]; nothing ever
//! handed it one from outside the process. This module is that missing half: it turns a file into
//! a validated profile, and a resolved run back into a file that reproduces it.
//!
//! Every refusal is named. A tuner that gets "rejected" learns nothing; a tuner that gets
//! `UnknownFamily { .. }` can fix its candidate.

use crate::modules::ModuleId;
use crate::params::{ParamClass, ParamDomainViolation};
use crate::{ProfileValue, ResolutionProfile, ResolutionValue, SourceKind};
use serde::{Deserialize, Serialize};

/// A profile document may not exceed this. It is a value set, not a payload; anything larger is a
/// mistake or an attack, and reading it into memory first would be the wrong way to find out.
pub const MAX_PROFILE_BYTES: usize = 1024 * 1024;

/// Document schema version. Bumping it is a published-surface change.
pub const PROFILE_DOCUMENT_SCHEMA_VERSION: u16 = 1;

/// A tier-2 parameter assignment, carried beside the tier-1 `values`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamAssignment {
    /// Tier-2 addressing id, as published by the export.
    pub param: String,
    pub value: ResolutionValue,
}

/// The on-disk profile document: tier-1 family values and tier-2 parameter assignments together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDocument {
    pub schema_version: u16,
    pub profile_id: String,
    pub registry_revision: u16,
    pub registry_digest: String,
    /// Tier-2 catalog digest. Optional so a tier-1-only document stays valid, but when present it
    /// is checked, because a candidate computed against a different parameter catalog is not the
    /// candidate this build would apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param_registry_digest: Option<String>,
    /// Restrict the document to one optimization module. Values outside it are refused, which is
    /// what makes single-module ablation possible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_scope: Option<ModuleId>,
    #[serde(default)]
    pub values: Vec<ProfileValue>,
    #[serde(default)]
    pub params: Vec<ParamAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileLoadError {
    TooLarge {
        bytes: usize,
        max: usize,
    },
    Malformed(String),
    DigestMismatch {
        expected: String,
        actual: String,
    },
    RegistryDigestMismatch {
        expected: String,
        actual: String,
    },
    RegistryRevisionMismatch {
        expected: u16,
        actual: u16,
    },
    ParamRegistryDigestMismatch {
        expected: String,
        actual: String,
    },
    SchemaVersion {
        expected: u16,
        actual: u16,
    },
    UnknownFamily(String),
    UnknownParam(String),
    UnauthorizedSource {
        family: String,
        source: SourceKind,
    },
    SealedFamily(String),
    StructuralParam(String),
    ParamDomain {
        param: String,
        reason: String,
    },
    DuplicateFamily(String),
    DuplicateParam(String),
    OutsideModuleScope {
        id: String,
        scope: ModuleId,
        actual: ModuleId,
    },
}

impl std::fmt::Display for ProfileLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { bytes, max } => {
                write!(
                    formatter,
                    "profile document is {bytes} bytes, over the {max}-byte bound"
                )
            }
            Self::Malformed(reason) => write!(formatter, "profile document is malformed: {reason}"),
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "profile file digest {actual} does not match the pinned digest {expected}"
            ),
            Self::RegistryDigestMismatch { expected, actual } => write!(
                formatter,
                "profile targets registry digest {actual}; this build is {expected}"
            ),
            Self::RegistryRevisionMismatch { expected, actual } => write!(
                formatter,
                "profile targets registry revision {actual}; this build is {expected}"
            ),
            Self::ParamRegistryDigestMismatch { expected, actual } => write!(
                formatter,
                "profile targets parameter catalog {actual}; this build is {expected}"
            ),
            Self::SchemaVersion { expected, actual } => write!(
                formatter,
                "profile document schema version {actual} is not {expected}"
            ),
            Self::UnknownFamily(id) => write!(formatter, "unknown family `{id}`"),
            Self::UnknownParam(id) => write!(formatter, "unknown parameter `{id}`"),
            Self::UnauthorizedSource { family, source } => write!(
                formatter,
                "family `{family}` cannot be set from {source:?}; a profile may only declare \
                 user_config or project_config"
            ),
            Self::SealedFamily(id) => write!(
                formatter,
                "family `{id}` is fixed-authority and can never be set by a profile"
            ),
            Self::StructuralParam(id) => write!(
                formatter,
                "parameter `{id}` is structural (identity, protocol or digest) and is exposed \
                 read-only"
            ),
            Self::ParamDomain { param, reason } => {
                write!(formatter, "parameter `{param}`: {reason}")
            }
            Self::DuplicateFamily(id) => write!(formatter, "family `{id}` is assigned twice"),
            Self::DuplicateParam(id) => write!(formatter, "parameter `{id}` is assigned twice"),
            Self::OutsideModuleScope { id, scope, actual } => write!(
                formatter,
                "`{id}` belongs to module {} but the profile is scoped to {}",
                actual.as_str(),
                scope.as_str()
            ),
        }
    }
}

impl std::error::Error for ProfileLoadError {}

/// Parse and fully validate a profile document.
///
/// `pinned_digest` is the caller-supplied expectation for the file's own SHA-256. It is required
/// rather than optional: a candidate that can be swapped between computing its digest and applying
/// it is not pinned to anything.
pub fn load_profile(
    bytes: &[u8],
    pinned_digest: &str,
) -> Result<ProfileDocument, ProfileLoadError> {
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(ProfileLoadError::TooLarge {
            bytes: bytes.len(),
            max: MAX_PROFILE_BYTES,
        });
    }
    let actual = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(bytes))
    };
    if !actual.eq_ignore_ascii_case(pinned_digest) {
        return Err(ProfileLoadError::DigestMismatch {
            expected: pinned_digest.to_owned(),
            actual,
        });
    }
    let document: ProfileDocument = serde_json::from_slice(bytes)
        .map_err(|error| ProfileLoadError::Malformed(error.to_string()))?;
    validate_profile(&document)?;
    Ok(document)
}

/// Validate an already-parsed document. Split out so a caller that built one in memory gets the
/// identical checks a loaded one gets.
pub fn validate_profile(document: &ProfileDocument) -> Result<(), ProfileLoadError> {
    if document.schema_version != PROFILE_DOCUMENT_SCHEMA_VERSION {
        return Err(ProfileLoadError::SchemaVersion {
            expected: PROFILE_DOCUMENT_SCHEMA_VERSION,
            actual: document.schema_version,
        });
    }
    if document.registry_digest != crate::REGISTRY_DIGEST_SHA256 {
        return Err(ProfileLoadError::RegistryDigestMismatch {
            expected: crate::REGISTRY_DIGEST_SHA256.to_owned(),
            actual: document.registry_digest.clone(),
        });
    }
    if document.registry_revision != crate::REGISTRY_REVISION {
        return Err(ProfileLoadError::RegistryRevisionMismatch {
            expected: crate::REGISTRY_REVISION,
            actual: document.registry_revision,
        });
    }
    if let Some(digest) = &document.param_registry_digest {
        let expected = crate::params::param_registry_digest_sha256();
        if digest != &expected {
            return Err(ProfileLoadError::ParamRegistryDigestMismatch {
                expected,
                actual: digest.clone(),
            });
        }
    }

    let mut seen_families = std::collections::BTreeSet::new();
    for value in &document.values {
        let family = crate::families()
            .iter()
            .find(|family| family.id == value.family)
            .ok_or_else(|| ProfileLoadError::UnknownFamily(value.family.clone()))?;
        if family.implementation_status == crate::ImplementationStatus::FixedHidden {
            return Err(ProfileLoadError::SealedFamily(family.id.to_owned()));
        }
        if !matches!(
            value.as_declared_source,
            SourceKind::UserConfig | SourceKind::ProjectConfig
        ) || !family
            .source
            .bindings
            .iter()
            .any(|binding| binding.kind == value.as_declared_source)
        {
            return Err(ProfileLoadError::UnauthorizedSource {
                family: family.id.to_owned(),
                source: value.as_declared_source,
            });
        }
        if !seen_families.insert(family.id) {
            return Err(ProfileLoadError::DuplicateFamily(family.id.to_owned()));
        }
        if let Some(scope) = document.module_scope {
            let actual = crate::modules::module_for(family);
            if actual != scope {
                return Err(ProfileLoadError::OutsideModuleScope {
                    id: family.id.to_owned(),
                    scope,
                    actual,
                });
            }
        }
    }

    let mut seen_params = std::collections::BTreeSet::new();
    for assignment in &document.params {
        let param = crate::params::param(&assignment.param)
            .ok_or_else(|| ProfileLoadError::UnknownParam(assignment.param.clone()))?;
        if matches!(param.class, ParamClass::Structural) {
            return Err(ProfileLoadError::StructuralParam(param.id.clone()));
        }
        if let ResolutionValue::Integer { value } = &assignment.value
            && let Err(violation) = param.admits_integer(i128::from(*value))
        {
            return Err(ProfileLoadError::ParamDomain {
                param: param.id.clone(),
                reason: match violation {
                    ParamDomainViolation::BelowMinimum { .. }
                    | ParamDomainViolation::AboveClamp { .. } => violation.to_string(),
                },
            });
        }
        if !seen_params.insert(param.id.clone()) {
            return Err(ProfileLoadError::DuplicateParam(param.id.clone()));
        }
        if let Some(scope) = document.module_scope
            && param.module != scope
        {
            return Err(ProfileLoadError::OutsideModuleScope {
                id: param.id.clone(),
                scope,
                actual: param.module,
            });
        }
    }
    Ok(())
}

/// Build an emittable document from a resolved profile, so a run can publish the exact input that
/// reproduces it.
pub fn emit_profile(profile: &ResolutionProfile) -> ProfileDocument {
    ProfileDocument {
        schema_version: PROFILE_DOCUMENT_SCHEMA_VERSION,
        profile_id: profile.profile_id.clone(),
        registry_revision: profile.registry_revision,
        registry_digest: profile.registry_digest.clone(),
        param_registry_digest: Some(crate::params::param_registry_digest_sha256()),
        module_scope: None,
        values: profile.values.clone(),
        params: Vec::new(),
    }
}

/// Serialize a document the way the loader expects to read it.
pub fn render_profile(document: &ProfileDocument) -> Result<String, ProfileLoadError> {
    let mut json = serde_json::to_string_pretty(document)
        .map_err(|error| ProfileLoadError::Malformed(error.to_string()))?;
    json.push('\n');
    Ok(json)
}

/// SHA-256 of a rendered document, so the emitter can print the digest the loader will demand.
pub fn document_digest(rendered: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(rendered.as_bytes()))
}
