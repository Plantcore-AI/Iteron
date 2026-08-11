//! Trusted composition-root adapter for the pure resolver.
//!
//! The registry and resolver deliberately do not read ambient state. This builder is the narrow
//! bridge used by a production composition root: owners submit already-resolved facts, the builder
//! binds them to registry-authorized sources, creates content-addressed evidence, and invokes the
//! same atomic resolver used by offline tooling. It contains no behavioral defaults.

use crate::{
    CatalogSnapshot, ConstraintEvidence, ConstraintRelation, ConstraintValue, CrossFieldRule,
    DeclaredValue, DefaultEvidence, DefaultResolver, EvidenceState, ExternalCeiling,
    ImplementationStatus, ProfileValue, ResolutionFailureReport, ResolutionInput,
    ResolutionProfile, ResolutionValue, ResolvedTunableSet, RouteCapabilities, RuntimeContext,
    SourceKind, families, resolve,
};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::BTreeSet;

#[path = "runtime_binding/activation.rs"]
mod activation;
#[path = "runtime_binding/authority.rs"]
mod authority;
#[path = "runtime_binding/effective.rs"]
mod effective;
#[path = "runtime_binding/evidence.rs"]
mod evidence;

pub use authority::RuntimeAuthoritySet;
use authority::validate_digest;
pub use effective::EffectiveValueError;
use evidence::{constraint_subject, default_subject, evidence_digest, resolver_id};

/// Named production profiles. A profile is provenance and a bounded group of ordinary declared
/// values; it is never a new authority layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    Interactive,
    Benchmark,
    Research,
}

impl RuntimeProfile {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Interactive => "iteron:interactive",
            Self::Benchmark => "iteron:benchmark",
            Self::Research => "iteron:research",
        }
    }

    pub const ALL: [Self; 3] = [Self::Interactive, Self::Benchmark, Self::Research];
}

/// Canonical identity of the named production profile before any ordinary declared values are
/// merged. Runtime checkpoints persist this digest; resume and operator surfaces use this helper
/// to recover the typed name without trusting current configuration.
pub fn runtime_profile_digest(profile: RuntimeProfile) -> Result<String, RuntimeResolutionError> {
    let value = ResolutionProfile {
        schema_version: crate::RESOLUTION_SCHEMA_VERSION,
        profile_id: profile.id().to_owned(),
        registry_revision: crate::REGISTRY_REVISION,
        registry_digest: crate::REGISTRY_DIGEST_SHA256.to_owned(),
        values: Vec::new(),
    };
    serde_json::to_vec(&value)
        .map(|bytes| hex::encode(sha2::Sha256::digest(bytes)))
        .map_err(|_| RuntimeResolutionError::EvidenceEncoding)
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeResolutionError {
    #[error("unknown tunable family `{0}`")]
    UnknownFamily(String),
    #[error("tunable family `{family}` does not authorize source `{source_kind:?}`")]
    UnauthorizedSource {
        family: String,
        source_kind: SourceKind,
    },
    #[error("duplicate runtime value for `{family}` from `{source_kind:?}`")]
    DuplicateValue {
        family: String,
        source_kind: SourceKind,
    },
    #[error("duplicate default evidence for `{0}`")]
    DuplicateDefault(String),
    #[error("duplicate constraint evidence for `{family}` field `{field}` ceiling `{ceiling:?}`")]
    DuplicateConstraint {
        family: String,
        field: String,
        ceiling: ExternalCeiling,
    },
    #[error(
        "constraint `{family}` field `{field}` ceiling `{ceiling:?}` is not registry-owned or has the wrong value kind"
    )]
    InvalidConstraint {
        family: String,
        field: String,
        ceiling: ExternalCeiling,
    },
    #[error("unknown scalar catalog `{0}`")]
    UnknownCatalog(String),
    #[error("invalid or missing SHA-256 authority digest for `{0}`")]
    InvalidAuthorityDigest(String),
    #[error("constraint ceiling `{0:?}` has no authenticated owner snapshot")]
    MissingConstraintAuthority(ExternalCeiling),
    #[error("tunable family `{0}` does not have runtime-derived activation")]
    NonRuntimeActivation(String),
    #[error(
        "runtime activation for family `{family}` declares seam `{observed}`; expected `{expected}`"
    )]
    MismatchedActivation {
        family: String,
        expected: String,
        observed: String,
    },
    #[error("duplicate runtime activation for family `{0}`")]
    DuplicateActivation(String),
    #[error("runtime activation for family `{family}` at seam `{seam}` was not observed")]
    MissingActivation { family: String, seam: String },
    #[error("runtime tunables evidence could not be encoded")]
    EvidenceEncoding,
    #[error("tunable family `{0}` uses a literal resolver and cannot accept default evidence")]
    LiteralEvidence(String),
    #[error("tunable family `{0}` is unavailable in this registry revision")]
    UnavailableFamily(String),
    #[error("runtime tunables failed atomic resolution: {0}")]
    Resolution(#[source] Box<ResolutionFailureReport>),
}

/// Build the canonical digest-bearing snapshot for one production scalar catalog.
///
/// Callers supply only owner-observed values; canonicalization remains in this crate so a CLI or
/// server composition root cannot accidentally hash the same catalog with a different envelope.
pub fn runtime_catalog_snapshot(
    catalog_id: impl Into<String>,
    values: BTreeSet<String>,
) -> Result<CatalogSnapshot, RuntimeResolutionError> {
    let mut snapshot = CatalogSnapshot {
        catalog_id: catalog_id.into(),
        digest_sha256: String::new(),
        values,
    };
    if !crate::SCALAR_CATALOGS
        .iter()
        .any(|definition| definition.id == snapshot.catalog_id)
    {
        return Err(RuntimeResolutionError::UnknownCatalog(snapshot.catalog_id));
    }
    snapshot.digest_sha256 = crate::resolution_prepare::catalog_content_digest(&snapshot)
        .map_err(|_| RuntimeResolutionError::EvidenceEncoding)?;
    Ok(snapshot)
}

impl From<ResolutionFailureReport> for RuntimeResolutionError {
    fn from(report: ResolutionFailureReport) -> Self {
        Self::Resolution(Box::new(report))
    }
}

/// Incremental, bounded input for one production resolution. Values are still validated only by
/// the canonical resolver; this type merely prevents every frontend from inventing evidence rules.
pub struct RuntimeResolutionBuilder {
    route: RouteCapabilities,
    authorities: RuntimeAuthoritySet,
    profile: ResolutionProfile,
    declared: Vec<DeclaredValue>,
    defaults: Vec<DefaultEvidence>,
    constraints: Vec<ConstraintEvidence>,
    activations: activation::EvidenceMap,
    catalogs: Vec<CatalogSnapshot>,
}

impl RuntimeResolutionBuilder {
    pub fn new(
        route: RouteCapabilities,
        catalogs: Vec<CatalogSnapshot>,
        profile: RuntimeProfile,
        authorities: RuntimeAuthoritySet,
    ) -> Result<Self, RuntimeResolutionError> {
        validate_digest("route_attestation", &route.attestation_digest_sha256)?;
        for catalog in &catalogs {
            if !crate::SCALAR_CATALOGS
                .iter()
                .any(|definition| definition.id == catalog.catalog_id)
            {
                return Err(RuntimeResolutionError::UnknownCatalog(
                    catalog.catalog_id.clone(),
                ));
            }
            validate_digest("catalog", &catalog.digest_sha256)?;
        }
        Ok(Self {
            route,
            authorities,
            profile: ResolutionProfile {
                schema_version: crate::RESOLUTION_SCHEMA_VERSION,
                profile_id: profile.id().to_owned(),
                registry_revision: crate::REGISTRY_REVISION,
                registry_digest: crate::REGISTRY_DIGEST_SHA256.to_owned(),
                values: Vec::new(),
            },
            declared: Vec::new(),
            defaults: Vec::new(),
            constraints: Vec::new(),
            activations: activation::EvidenceMap::new(),
            catalogs,
        })
    }

    /// Add one value from an already-resolved, registry-authorized source.
    pub fn declare(
        &mut self,
        family_id: &str,
        source: SourceKind,
        value: ResolutionValue,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        let family = family(family_id)?;
        if family.implementation_status == ImplementationStatus::Missing {
            return Err(RuntimeResolutionError::UnavailableFamily(
                family_id.to_owned(),
            ));
        }
        if !family
            .source
            .bindings
            .iter()
            .any(|binding| binding.kind == source)
        {
            return Err(RuntimeResolutionError::UnauthorizedSource {
                family: family.id.to_owned(),
                source_kind: source,
            });
        }
        if self
            .declared
            .iter()
            .any(|candidate| candidate.family == family.id && candidate.source == source)
        {
            return Err(RuntimeResolutionError::DuplicateValue {
                family: family.id.to_owned(),
                source_kind: source,
            });
        }
        let evidence_digest_sha256 = evidence_digest(
            "declared-value",
            &(family.id, source, &value, crate::REGISTRY_DIGEST_SHA256),
        )?;
        self.declared.push(DeclaredValue {
            family: family.id.to_owned(),
            source,
            evidence_digest_sha256,
            value,
        });
        Ok(self)
    }

    /// Add a profile value. Only user/project-config bindings are accepted by the resolver.
    pub fn profile_value(
        &mut self,
        family_id: &str,
        source: SourceKind,
        value: ResolutionValue,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        let family = family(family_id)?;
        if family.implementation_status == ImplementationStatus::Missing {
            return Err(RuntimeResolutionError::UnavailableFamily(
                family.id.to_owned(),
            ));
        }
        if !matches!(source, SourceKind::UserConfig | SourceKind::ProjectConfig)
            || !family
                .source
                .bindings
                .iter()
                .any(|binding| binding.kind == source)
        {
            return Err(RuntimeResolutionError::UnauthorizedSource {
                family: family.id.to_owned(),
                source_kind: source,
            });
        }
        if self.profile.values.iter().any(|candidate| {
            candidate.family == family.id && candidate.as_declared_source == source
        }) {
            return Err(RuntimeResolutionError::DuplicateValue {
                family: family.id.to_owned(),
                source_kind: source,
            });
        }
        self.profile.values.push(ProfileValue {
            family: family.id.to_owned(),
            as_declared_source: source,
            value,
        });
        Ok(self)
    }

    /// Bind the value returned by a named default resolver. Literal defaults are registry bytes
    /// already and therefore do not accept an attestation.
    pub fn observe_default(
        &mut self,
        family_id: &str,
        value: ResolutionValue,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        self.observe_default_state(family_id, EvidenceState::Present { value })
    }

    pub fn observe_default_absent(
        &mut self,
        family_id: &str,
        code: impl Into<String>,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        self.observe_default_state(family_id, EvidenceState::Absent { code: code.into() })
    }

    pub fn observe_default_unsupported(
        &mut self,
        family_id: &str,
        code: impl Into<String>,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        self.observe_default_state(family_id, EvidenceState::Unsupported { code: code.into() })
    }

    fn observe_default_state(
        &mut self,
        family_id: &str,
        state: EvidenceState,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        let family = family(family_id)?;
        if family.implementation_status == ImplementationStatus::Missing {
            return Err(RuntimeResolutionError::UnavailableFamily(
                family_id.to_owned(),
            ));
        }
        if matches!(family.default.resolver, DefaultResolver::Literal) {
            return Err(RuntimeResolutionError::LiteralEvidence(
                family.id.to_owned(),
            ));
        }
        if self
            .defaults
            .iter()
            .any(|candidate| candidate.family == family.id)
        {
            return Err(RuntimeResolutionError::DuplicateDefault(
                family.id.to_owned(),
            ));
        }
        let subject = default_subject(
            family.default.resolver,
            &self.route.route,
            &self.authorities.operator_digest_sha256,
            &state,
        )?;
        self.defaults.push(DefaultEvidence {
            family: family.id.to_owned(),
            resolver_id: resolver_id(family.default.resolver),
            evidence_digest_sha256: evidence_digest(
                "default-evidence",
                &(family.id, &subject, &state),
            )?,
            subject,
            state,
        });
        Ok(self)
    }

    /// Add a ceiling fact from the authority that owns it. The caller supplies the attested value;
    /// this builder supplies only the registry-owned identity and subject binding. In particular,
    /// the requested tunable value is never reused as its own ceiling.
    pub fn constrain(
        &mut self,
        family_id: &str,
        field: &str,
        ceiling: ExternalCeiling,
        value: ConstraintValue,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        let family = family(family_id)?;
        if family.implementation_status == ImplementationStatus::Missing {
            return Err(RuntimeResolutionError::UnavailableFamily(
                family.id.to_owned(),
            ));
        }
        let valid = family.value_schema.rules.iter().any(|rule| {
            matches!(
                (rule, &value),
                (
                    CrossFieldRule::ExternalCeiling {
                        field: candidate,
                        ceiling: candidate_ceiling,
                        relation: ConstraintRelation::UpperBound,
                        ..
                    },
                    ConstraintValue::UpperBound { .. }
                ) if *candidate == field && *candidate_ceiling == ceiling
            ) || matches!(
                (rule, &value),
                (
                    CrossFieldRule::ExternalCeiling {
                        field: candidate,
                        ceiling: candidate_ceiling,
                        relation: ConstraintRelation::Exact,
                        ..
                    },
                    ConstraintValue::Exact { .. }
                ) if *candidate == field && *candidate_ceiling == ceiling
            ) || matches!(
                (rule, &value),
                (
                    CrossFieldRule::ExternalCeiling {
                        field: candidate,
                        ceiling: candidate_ceiling,
                        relation: ConstraintRelation::AttestedDomain,
                        ..
                    },
                    ConstraintValue::Domain { .. }
                ) if *candidate == field && *candidate_ceiling == ceiling
            )
        });
        if !valid {
            return Err(RuntimeResolutionError::InvalidConstraint {
                family: family.id.to_owned(),
                field: field.to_owned(),
                ceiling,
            });
        }
        if self.constraints.iter().any(|candidate| {
            candidate.family == family.id
                && candidate.field == field
                && candidate.ceiling == ceiling
        }) {
            return Err(RuntimeResolutionError::DuplicateConstraint {
                family: family.id.to_owned(),
                field: field.to_owned(),
                ceiling,
            });
        }
        let owner_digest = self
            .authorities
            .digest_for(ceiling, &self.route.attestation_digest_sha256)?;
        let subject = constraint_subject(ceiling, &self.route.route, &owner_digest);
        self.constraints.push(ConstraintEvidence {
            family: family.id.to_owned(),
            field: field.to_owned(),
            ceiling,
            evidence_digest_sha256: evidence_digest(
                "external-ceiling",
                &(family.id, field, ceiling, &subject, owner_digest, &value),
            )?,
            subject,
            value,
        });
        Ok(self)
    }

    /// Record one authenticated entry for one runtime-derived family. The family and its declared
    /// seam are both required because a production seam may own several independent tunables.
    pub fn activate(
        &mut self,
        family_id: &str,
        seam: &str,
        active: bool,
        subject_digest_sha256: impl Into<String>,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        activation::observe(
            &mut self.activations,
            family_id,
            seam,
            active,
            subject_digest_sha256,
        )?;
        Ok(self)
    }

    /// Resolve atomically. The complete runtime-derived seam inventory is mandatory; a forgotten
    /// production binding is not equivalent to an authenticated inactive observation.
    pub fn resolve(self) -> Result<ResolvedTunableSet, RuntimeResolutionError> {
        activation::require_complete(&self.activations)?;
        let input = ResolutionInput {
            schema_version: crate::RESOLUTION_SCHEMA_VERSION,
            registry_id: crate::REGISTRY_ID.to_owned(),
            registry_revision: crate::REGISTRY_REVISION,
            registry_digest: crate::REGISTRY_DIGEST_SHA256.to_owned(),
            profile: Some(self.profile),
            declared_values: self.declared,
            default_evidence: self.defaults,
            activation_evidence: self.activations.into_values().collect(),
            constraint_evidence: self.constraints,
            runtime: RuntimeContext {
                selected_route: Some(self.route.route.clone()),
                admitted_routes: vec![self.route],
                catalogs: self.catalogs,
            },
        };
        resolve(input).map_err(RuntimeResolutionError::from)
    }
}

fn family(id: &str) -> Result<&'static crate::Family, RuntimeResolutionError> {
    families()
        .iter()
        .find(|family| family.id == id || family.aliases.contains(&id))
        .ok_or_else(|| RuntimeResolutionError::UnknownFamily(id.to_owned()))
}
