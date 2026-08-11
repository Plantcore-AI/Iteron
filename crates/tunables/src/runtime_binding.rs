//! Trusted composition-root adapter for the pure resolver.
//!
//! The registry and resolver deliberately do not read ambient state. This builder is the narrow
//! bridge used by a production composition root: owners submit already-resolved facts, the builder
//! binds them to registry-authorized sources, creates content-addressed evidence, and invokes the
//! same atomic resolver used by offline tooling. It contains no behavioral defaults.

use crate::{
    CatalogSnapshot, ConstraintEvidence, ConstraintRelation, ConstraintValue, CrossFieldRule,
    DeclaredValue, DefaultEvidence, DefaultResolver, EvidenceState, ExternalCeiling,
    FixedAuthorityAttestation, FixedAuthorityId, ImplementationStatus, ProductionOwnerId,
    ProductionOwnerSymbolId, ProfileValue, ResolutionFailureReport, ResolutionInput,
    ResolutionProfile, ResolutionValue, ResolvedTunableSet, RouteCapabilities, RuntimeBindingSpec,
    RuntimeContext, SourceKind, families, resolve,
};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};

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
    #[error("production owner value for literal family `{0}` differs from the canonical value")]
    LiteralOwnerMismatch(String),
    #[error("effective literal family `{0}` has no executed canonical-owner attestation")]
    MissingLiteralOwnerAttestation(String),
    #[error("tunable family `{0}` is not governed by a fixed runtime authority")]
    NonFixedAuthorityFamily(String),
    #[error(
        "fixed authority `{observed:?}` cannot bind family `{family}` governed by `{expected:?}`"
    )]
    MismatchedFixedAuthority {
        family: String,
        expected: FixedAuthorityId,
        observed: FixedAuthorityId,
    },
    #[error("duplicate fixed-authority attestation for `{0}`")]
    DuplicateFixedAuthorityAttestation(String),
    #[error("effective fixed family `{0}` has no executed fixed-authority attestation")]
    MissingFixedAuthorityAttestation(String),
    #[error("fixed-authority owner value for `{0}` differs from the resolved effective value")]
    FixedAuthorityValueMismatch(String),
    #[error("inactive fixed family `{0}` unexpectedly carries a fixed-authority attestation")]
    InactiveFixedAuthorityAttestation(String),
    #[error(
        "production owner `{observed:?}` cannot bind family `{family}` owned by `{expected:?}`"
    )]
    MismatchedProductionOwner {
        family: String,
        expected: ProductionOwnerId,
        observed: ProductionOwnerId,
    },
    #[error("effective family `{0}` has no executed production-owner binding")]
    MissingProductionOwner(String),
    #[error(
        "production owner symbol `{observed:?}` cannot bind family `{family}` owned by `{expected:?}`"
    )]
    MismatchedProductionOwnerSymbol {
        family: String,
        expected: ProductionOwnerSymbolId,
        observed: ProductionOwnerSymbolId,
    },
    #[error("effective family `{0}` has no executed concrete production-owner symbol")]
    MissingProductionOwnerSymbol(String),
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
    active_owner: Option<ProductionOwnerId>,
    owner_observations: BTreeMap<String, ProductionOwnerId>,
    owner_symbol_observations: BTreeMap<String, ProductionOwnerSymbolId>,
    literal_owner_attestations: BTreeSet<String>,
    fixed_authority_observations: BTreeMap<String, (FixedAuthorityId, ResolutionValue)>,
}

/// Sealed result of executing the production owner adapters for every active Full family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOwnerReceipt {
    observations: BTreeMap<String, (ProductionOwnerId, ProductionOwnerSymbolId)>,
    fixed_observations: BTreeMap<String, (ProductionOwnerId, FixedAuthorityId, String)>,
}

impl RuntimeOwnerReceipt {
    pub fn family_count(&self) -> usize {
        self.observations.len()
    }

    pub fn contains(
        &self,
        family: &str,
        adapter: ProductionOwnerId,
        owner: ProductionOwnerSymbolId,
    ) -> bool {
        self.observations.get(family) == Some(&(adapter, owner))
    }

    pub fn fixed_family_count(&self) -> usize {
        self.fixed_observations.len()
    }

    pub fn contains_fixed(
        &self,
        family: &str,
        adapter: ProductionOwnerId,
        authority: FixedAuthorityId,
        owner_value_digest_sha256: &str,
    ) -> bool {
        self.fixed_observations.get(family)
            == Some(&(adapter, authority, owner_value_digest_sha256.to_owned()))
    }
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
            active_owner: None,
            owner_observations: BTreeMap::new(),
            owner_symbol_observations: BTreeMap::new(),
            literal_owner_attestations: BTreeSet::new(),
            fixed_authority_observations: BTreeMap::new(),
        })
    }

    /// Execute one typed production-owner adapter. Only family operations actually performed by
    /// the closure mint observations; opening a scope alone proves nothing.
    pub fn with_owner<T, E>(
        &mut self,
        owner: ProductionOwnerId,
        apply: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        assert!(
            self.active_owner.is_none(),
            "runtime tunables owner scopes must not nest"
        );
        self.active_owner = Some(owner);
        let result = apply(self);
        self.active_owner = None;
        result
    }

    fn observe_owner(
        &mut self,
        family: &'static crate::Family,
    ) -> Result<(), RuntimeResolutionError> {
        let Some(observed) = self.active_owner else {
            // Offline resolution remains supported. Production uses
            // `resolve_with_owner_receipt`, which rejects every missing observation.
            return Ok(());
        };
        let expected = family.runtime_binding.adapter();
        if observed != expected {
            return Err(RuntimeResolutionError::MismatchedProductionOwner {
                family: family.id.to_owned(),
                expected,
                observed,
            });
        }
        self.owner_observations
            .insert(family.id.to_owned(), observed);
        Ok(())
    }

    /// Submit the concrete typed owner sampled by the current production adapter. A symbol can
    /// only attach to a family already touched by an actual builder operation in this adapter;
    /// listing a family without executing its owner path mints no receipt.
    pub fn submit_owner_symbol(
        &mut self,
        symbol: ProductionOwnerSymbolId,
        family_ids: &[&str],
    ) -> Result<&mut Self, RuntimeResolutionError> {
        let Some(active_adapter) = self.active_owner else {
            return Ok(self);
        };
        for family_id in family_ids {
            let family = family(family_id)?;
            let RuntimeBindingSpec::Effective {
                adapter,
                owner: expected,
                ..
            } = family.runtime_binding
            else {
                continue;
            };
            if expected != symbol {
                return Err(RuntimeResolutionError::MismatchedProductionOwnerSymbol {
                    family: family.id.to_owned(),
                    expected,
                    observed: symbol,
                });
            }
            if adapter != active_adapter {
                return Err(RuntimeResolutionError::MismatchedProductionOwner {
                    family: family.id.to_owned(),
                    expected: adapter,
                    observed: active_adapter,
                });
            }
            if self.owner_observations.get(family.id) == Some(&adapter) {
                self.owner_symbol_observations
                    .insert(family.id.to_owned(), symbol);
            }
        }
        Ok(self)
    }

    /// Add one value from an already-resolved, registry-authorized source.
    pub fn declare(
        &mut self,
        family_id: &str,
        source: SourceKind,
        value: ResolutionValue,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        let family = family(family_id)?;
        self.observe_owner(family)?;
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
        if source == SourceKind::Builtin
            && matches!(family.default.resolver, DefaultResolver::Literal)
        {
            let Some(expected) = family.default.value.map(crate::resolution_value::owned) else {
                return Err(RuntimeResolutionError::LiteralOwnerMismatch(
                    family.id.to_owned(),
                ));
            };
            let mut observed = value.clone();
            let mut expected = expected;
            crate::resolution_value::normalize(&mut observed);
            crate::resolution_value::normalize(&mut expected);
            if observed != expected {
                return Err(RuntimeResolutionError::LiteralOwnerMismatch(
                    family.id.to_owned(),
                ));
            }
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
        self.observe_owner(family)?;
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
        self.observe_owner(family)?;
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

    /// Prove that an executable owner which is intentionally fixed in source still matches the
    /// canonical literal used by the pure resolver. Unlike `observe_default`, this does not add a
    /// second value source: it compares the typed owner value byte-for-byte and only then records
    /// that the production adapter actually sampled the owner.
    pub fn attest_literal_owner(
        &mut self,
        family_id: &str,
        observed: ResolutionValue,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        let family = family(family_id)?;
        if !matches!(family.default.resolver, DefaultResolver::Literal) {
            return Err(RuntimeResolutionError::LiteralEvidence(
                family.id.to_owned(),
            ));
        }
        let Some(expected) = family.default.value.map(crate::resolution_value::owned) else {
            return Err(RuntimeResolutionError::LiteralOwnerMismatch(
                family.id.to_owned(),
            ));
        };
        if observed != expected {
            return Err(RuntimeResolutionError::LiteralOwnerMismatch(
                family.id.to_owned(),
            ));
        }
        self.observe_owner(family)?;
        self.literal_owner_attestations.insert(family.id.to_owned());
        Ok(self)
    }

    /// Execute one non-replaceable physical owner and bind its exact canonical value to the
    /// registry's fixed authority. The caller must name the closed authority enum explicitly so
    /// an adapter wired to the wrong owner fails before resolution. Merely declaring a resolver
    /// candidate or matching the value schema cannot mint this receipt.
    pub fn attest_fixed_authority(
        &mut self,
        family_id: &str,
        authority: FixedAuthorityId,
        observed: ResolutionValue,
    ) -> Result<&mut Self, RuntimeResolutionError> {
        let family = family(family_id)?;
        let RuntimeBindingSpec::Fixed {
            authority: expected,
            ..
        } = family.runtime_binding
        else {
            return Err(RuntimeResolutionError::NonFixedAuthorityFamily(
                family.id.to_owned(),
            ));
        };
        if authority != expected {
            return Err(RuntimeResolutionError::MismatchedFixedAuthority {
                family: family.id.to_owned(),
                expected,
                observed: authority,
            });
        }
        self.observe_owner(family)?;
        if self.fixed_authority_observations.contains_key(family.id) {
            return Err(RuntimeResolutionError::DuplicateFixedAuthorityAttestation(
                family.id.to_owned(),
            ));
        }
        self.fixed_authority_observations
            .insert(family.id.to_owned(), (authority, observed));
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
        self.observe_owner(family)?;
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
        let family = family(family_id)?;
        self.observe_owner(family)?;
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
        let (resolved, _, _, _, _) = self.resolve_internal()?;
        Ok(resolved)
    }

    /// Production-only atomic resolution. Success additionally proves that the actual owner
    /// adapter touched every family which resolved Effective and is canonically `Full`.
    pub fn resolve_with_owner_receipt(
        self,
    ) -> Result<(ResolvedTunableSet, RuntimeOwnerReceipt), RuntimeResolutionError> {
        self.validate_declared_literal_owner_attestations()?;
        let (
            mut resolved,
            observations,
            symbol_observations,
            literal_owner_attestations,
            fixed_authority_observations,
        ) = self.resolve_internal()?;
        let mut receipt = BTreeMap::new();
        let mut fixed_receipt = BTreeMap::new();
        let mut fixed_attestations = Vec::new();
        for entry in &resolved.report().entries {
            let family = family(entry.family_id)?;
            if !matches!(entry.outcome, crate::EntryOutcome::Effective) {
                if matches!(family.runtime_binding, RuntimeBindingSpec::Fixed { .. })
                    && fixed_authority_observations.contains_key(family.id)
                {
                    return Err(RuntimeResolutionError::InactiveFixedAuthorityAttestation(
                        family.id.to_owned(),
                    ));
                }
                continue;
            }
            match family.runtime_binding {
                RuntimeBindingSpec::Effective { adapter, owner, .. } => {
                    if matches!(family.default.resolver, DefaultResolver::Literal)
                        && !literal_owner_attestations.contains(family.id)
                    {
                        return Err(RuntimeResolutionError::MissingLiteralOwnerAttestation(
                            family.id.to_owned(),
                        ));
                    }
                    if observations.get(family.id) != Some(&adapter) {
                        return Err(RuntimeResolutionError::MissingProductionOwner(
                            family.id.to_owned(),
                        ));
                    }
                    if symbol_observations.get(family.id) != Some(&owner) {
                        return Err(RuntimeResolutionError::MissingProductionOwnerSymbol(
                            family.id.to_owned(),
                        ));
                    }
                    receipt.insert(family.id.to_owned(), (adapter, owner));
                }
                RuntimeBindingSpec::Fixed {
                    adapter, authority, ..
                } => {
                    let Some((observed_authority, observed_value)) =
                        fixed_authority_observations.get(family.id)
                    else {
                        return Err(RuntimeResolutionError::MissingFixedAuthorityAttestation(
                            family.id.to_owned(),
                        ));
                    };
                    if *observed_authority != authority {
                        return Err(RuntimeResolutionError::MismatchedFixedAuthority {
                            family: family.id.to_owned(),
                            expected: authority,
                            observed: *observed_authority,
                        });
                    }
                    if observations.get(family.id) != Some(&adapter) {
                        return Err(RuntimeResolutionError::MissingProductionOwner(
                            family.id.to_owned(),
                        ));
                    }
                    let Some(effective) = entry.effective.as_ref() else {
                        return Err(RuntimeResolutionError::FixedAuthorityValueMismatch(
                            family.id.to_owned(),
                        ));
                    };
                    let observed_digest =
                        fixed_authority_value_digest_sha256(family.id, authority, observed_value)?;
                    let effective_digest =
                        fixed_authority_value_digest_sha256(family.id, authority, effective)?;
                    if observed_digest != effective_digest {
                        return Err(RuntimeResolutionError::FixedAuthorityValueMismatch(
                            family.id.to_owned(),
                        ));
                    }
                    let attestation = FixedAuthorityAttestation {
                        family_id: family.id.to_owned(),
                        authority,
                        owner_value_digest_sha256: effective_digest.clone(),
                    };
                    fixed_receipt
                        .insert(family.id.to_owned(), (adapter, authority, effective_digest));
                    fixed_attestations.push(attestation);
                }
                RuntimeBindingSpec::Unbound { .. } => {
                    return Err(RuntimeResolutionError::MissingProductionOwner(
                        family.id.to_owned(),
                    ));
                }
            }
        }
        if fixed_attestations.len() > crate::EXPECTED_FAMILY_COUNT {
            return Err(RuntimeResolutionError::EvidenceEncoding);
        }
        resolved.report.fixed_authority_attestations = fixed_attestations;
        resolved.report.resolution_digest_sha256 =
            crate::resolution_digest::resolution_digest(&resolved.report)
                .map_err(|_| RuntimeResolutionError::EvidenceEncoding)?;
        Ok((
            resolved,
            RuntimeOwnerReceipt {
                observations: receipt,
                fixed_observations: fixed_receipt,
            },
        ))
    }

    /// A selected override is not evidence that the executable fallback owner still matches the
    /// registry literal. Production composition must execute both seams: first attest the fixed
    /// owner, then submit the independently authorized override. Offline resolution remains able
    /// to model candidates without claiming a production-owner receipt.
    fn validate_declared_literal_owner_attestations(&self) -> Result<(), RuntimeResolutionError> {
        for candidate in &self.declared {
            let family = family(&candidate.family)?;
            if matches!(family.default.resolver, DefaultResolver::Literal)
                && matches!(family.runtime_binding, RuntimeBindingSpec::Effective { .. })
                && !self.literal_owner_attestations.contains(family.id)
            {
                return Err(RuntimeResolutionError::MissingLiteralOwnerAttestation(
                    family.id.to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn resolve_internal(
        self,
    ) -> Result<
        (
            ResolvedTunableSet,
            BTreeMap<String, ProductionOwnerId>,
            BTreeMap<String, ProductionOwnerSymbolId>,
            BTreeSet<String>,
            BTreeMap<String, (FixedAuthorityId, ResolutionValue)>,
        ),
        RuntimeResolutionError,
    > {
        activation::require_complete(&self.activations)?;
        let observations = self.owner_observations;
        let symbol_observations = self.owner_symbol_observations;
        let literal_owner_attestations = self.literal_owner_attestations;
        let fixed_authority_observations = self.fixed_authority_observations;
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
        let resolved = resolve(input).map_err(RuntimeResolutionError::from)?;
        Ok((
            resolved,
            observations,
            symbol_observations,
            literal_owner_attestations,
            fixed_authority_observations,
        ))
    }
}

/// Domain-separated, registry-bound digest of one fixed authority's exact canonical value.
/// The family and authority are validated against the closed registry before any digest is
/// returned, so callers cannot reuse a value receipt across families or authority classes.
pub fn fixed_authority_value_digest_sha256(
    family_id: &str,
    authority: FixedAuthorityId,
    value: &ResolutionValue,
) -> Result<String, RuntimeResolutionError> {
    let family = family(family_id)?;
    let RuntimeBindingSpec::Fixed {
        authority: expected,
        ..
    } = family.runtime_binding
    else {
        return Err(RuntimeResolutionError::NonFixedAuthorityFamily(
            family.id.to_owned(),
        ));
    };
    if authority != expected {
        return Err(RuntimeResolutionError::MismatchedFixedAuthority {
            family: family.id.to_owned(),
            expected,
            observed: authority,
        });
    }
    let mut value = value.clone();
    crate::resolution_value::normalize(&mut value);
    let canonical = serde_json::to_vec(&(
        crate::REGISTRY_ID,
        crate::REGISTRY_REVISION,
        crate::REGISTRY_DIGEST_SHA256,
        family.id,
        authority,
        value,
    ))
    .map_err(|_| RuntimeResolutionError::EvidenceEncoding)?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"iteron-fixed-authority-value-v1\0");
    hasher.update(
        u64::try_from(canonical.len())
            .map_err(|_| RuntimeResolutionError::EvidenceEncoding)?
            .to_be_bytes(),
    );
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

/// Manufacture content-free fixed-authority bindings for resolver-only test fixtures.
///
/// This function is absent from production builds. It exists solely because downstream tests
/// intentionally construct a complete pure-resolver report without executing the CLI's typed
/// owner adapters, while the V2 projector correctly refuses such a report in production.
#[cfg(feature = "test-fixtures")]
pub fn with_synthetic_fixed_authority_attestations_for_test(
    mut resolved: ResolvedTunableSet,
) -> Result<ResolvedTunableSet, RuntimeResolutionError> {
    let mut attestations = Vec::new();
    for entry in &resolved.report.entries {
        if !matches!(entry.outcome, crate::EntryOutcome::Effective) {
            continue;
        }
        let family = family(entry.family_id)?;
        let RuntimeBindingSpec::Fixed { authority, .. } = family.runtime_binding else {
            continue;
        };
        let value = entry.effective.as_ref().ok_or_else(|| {
            RuntimeResolutionError::FixedAuthorityValueMismatch(family.id.to_owned())
        })?;
        attestations.push(FixedAuthorityAttestation {
            family_id: family.id.to_owned(),
            authority,
            owner_value_digest_sha256: fixed_authority_value_digest_sha256(
                family.id, authority, value,
            )?,
        });
    }
    resolved.report.fixed_authority_attestations = attestations;
    resolved.report.resolution_digest_sha256 =
        crate::resolution_digest::resolution_digest(&resolved.report)
            .map_err(|_| RuntimeResolutionError::EvidenceEncoding)?;
    Ok(resolved)
}

fn family(id: &str) -> Result<&'static crate::Family, RuntimeResolutionError> {
    families()
        .iter()
        .find(|family| family.id == id || family.aliases.contains(&id))
        .ok_or_else(|| RuntimeResolutionError::UnknownFamily(id.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn builder() -> RuntimeResolutionBuilder {
        RuntimeResolutionBuilder::new(
            RouteCapabilities {
                route: crate::RouteIdentity {
                    provider_id: "glm".to_owned(),
                    model_id: "glm-5.2".to_owned(),
                    route_revision: "literal-owner-test-v1".to_owned(),
                    catalog_digest_sha256: DIGEST_A.to_owned(),
                },
                capabilities: BTreeSet::new(),
                attestation_digest_sha256: DIGEST_B.to_owned(),
            },
            Vec::new(),
            RuntimeProfile::Interactive,
            RuntimeAuthoritySet::new(DIGEST_A).expect("valid authority digest"),
        )
        .expect("valid builder")
    }

    #[test]
    fn production_literal_override_requires_the_executed_literal_owner_first() {
        let selected = ResolutionValue::List {
            items: vec![ResolutionValue::Enum {
                value: "fixture:fallback".to_owned(),
            }],
        };

        let mut unbacked = builder();
        unbacked
            .declare(
                "model_fallback_chain",
                SourceKind::UserConfig,
                selected.clone(),
            )
            .expect("the operator override is an authorized candidate");
        assert!(matches!(
            unbacked.validate_declared_literal_owner_attestations(),
            Err(RuntimeResolutionError::MissingLiteralOwnerAttestation(family))
                if family == "model_fallback_chain"
        ));

        let mut backed = builder();
        backed
            .attest_literal_owner(
                "model_fallback_chain",
                ResolutionValue::List { items: Vec::new() },
            )
            .expect("the physical empty fallback owner matches the registry literal");
        backed
            .declare("model_fallback_chain", SourceKind::UserConfig, selected)
            .expect("the independently authorized override remains selectable");
        backed
            .validate_declared_literal_owner_attestations()
            .expect("attestation plus override is a complete production claim");
    }

    #[test]
    fn fixed_authority_attestation_rejects_wrong_authority_and_duplicates() {
        let family = "provider_discovery_account_probe_cache_policy";
        let value = ResolutionValue::Object {
            fields: BTreeMap::new(),
        };
        let mut wrong = builder();
        assert!(matches!(
            wrong.attest_fixed_authority(
                family,
                FixedAuthorityId::RuntimeInvariant,
                value.clone(),
            ),
            Err(RuntimeResolutionError::MismatchedFixedAuthority {
                family: rejected,
                expected: FixedAuthorityId::ProviderDiscoveryBootstrap,
                observed: FixedAuthorityId::RuntimeInvariant,
            }) if rejected == family
        ));

        let mut duplicate = builder();
        duplicate
            .attest_fixed_authority(
                family,
                FixedAuthorityId::ProviderDiscoveryBootstrap,
                value.clone(),
            )
            .expect("the exact authority may attest once");
        assert!(matches!(
            duplicate.attest_fixed_authority(
                family,
                FixedAuthorityId::ProviderDiscoveryBootstrap,
                value,
            ),
            Err(RuntimeResolutionError::DuplicateFixedAuthorityAttestation(rejected))
                if rejected == family
        ));
    }

    #[test]
    fn fixed_authority_digest_is_bound_to_registry_family_authority_and_value() {
        let family = "provider_discovery_account_probe_cache_policy";
        let first = ResolutionValue::Object {
            fields: BTreeMap::new(),
        };
        let second = ResolutionValue::Object {
            fields: [(
                "eager_budget_milliseconds".to_owned(),
                ResolutionValue::Integer { value: 1 },
            )]
            .into_iter()
            .collect(),
        };
        let first_digest = fixed_authority_value_digest_sha256(
            family,
            FixedAuthorityId::ProviderDiscoveryBootstrap,
            &first,
        )
        .expect("registered fixed authority hashes");
        let second_digest = fixed_authority_value_digest_sha256(
            family,
            FixedAuthorityId::ProviderDiscoveryBootstrap,
            &second,
        )
        .expect("registered fixed authority hashes");
        assert_ne!(first_digest, second_digest);
        assert!(matches!(
            fixed_authority_value_digest_sha256(family, FixedAuthorityId::RuntimeInvariant, &first,),
            Err(RuntimeResolutionError::MismatchedFixedAuthority { .. })
        ));
    }
}
