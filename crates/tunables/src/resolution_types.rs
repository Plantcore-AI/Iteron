use crate::{CapabilityRequirement, DecimalValue, ExternalCeiling, SourceKind};
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod report;
pub use report::*;

pub const RESOLUTION_SCHEMA_VERSION: u16 = 2;
pub const RESOLUTION_INPUT_MAX_BYTES: usize = 1_048_576;
pub(crate) const MAX_DECLARED_VALUES: usize = 193;
pub(crate) const MAX_PROFILE_VALUES: usize = crate::EXPECTED_FAMILY_COUNT;
pub(crate) const MAX_DEFAULT_EVIDENCE: usize = 106;
pub(crate) const MAX_ACTIVATION_EVIDENCE: usize = 53;
pub(crate) const MAX_CONSTRAINTS: usize = 201;
pub(crate) const MAX_ROUTES: usize = 16;
pub(crate) const MAX_CATALOGS: usize = 64;
pub(crate) const MAX_CATALOG_VALUES: usize = 4_096;
pub(crate) const MAX_ID_BYTES: usize = 256;

/// Owned, float-free runtime value. Ordered maps make canonicalization independent of insertion
/// order. Large catalog families use a content-addressed reference rather than copying payloads
/// into every resolution report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolutionValue {
    Boolean {
        value: bool,
    },
    Integer {
        value: i64,
    },
    Decimal {
        value: DecimalValue,
    },
    Text {
        value: String,
    },
    Enum {
        value: String,
    },
    List {
        items: Vec<ResolutionValue>,
    },
    Map {
        entries: BTreeMap<String, ResolutionValue>,
    },
    Object {
        fields: BTreeMap<String, ResolutionValue>,
    },
    CatalogRef {
        catalog_id: String,
        digest_sha256: String,
        entry_count: u64,
        canonical_bytes: u64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RawResolutionValue {
    Boolean {
        value: bool,
    },
    Integer {
        value: i64,
    },
    Decimal {
        value: DecimalValue,
    },
    Text {
        value: String,
    },
    Enum {
        value: String,
    },
    List {
        items: Vec<ResolutionValue>,
    },
    Map {
        entries: UniqueStringMap,
    },
    Object {
        fields: UniqueStringMap,
    },
    CatalogRef {
        catalog_id: String,
        digest_sha256: String,
        entry_count: u64,
        canonical_bytes: u64,
    },
}

#[derive(Debug)]
struct UniqueStringMap(BTreeMap<String, ResolutionValue>);

impl<'de> Deserialize<'de> for UniqueStringMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueMapVisitor;

        impl<'de> Visitor<'de> for UniqueMapVisitor {
            type Value = UniqueStringMap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object with unique field names")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, ResolutionValue>()? {
                    if entries.insert(key.clone(), value).is_some() {
                        return Err(A::Error::custom(format!(
                            "duplicate map/object field `{key}`"
                        )));
                    }
                }
                Ok(UniqueStringMap(entries))
            }
        }

        deserializer.deserialize_map(UniqueMapVisitor)
    }
}

impl<'de> Deserialize<'de> for ResolutionValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match RawResolutionValue::deserialize(deserializer)? {
            RawResolutionValue::Boolean { value } => Self::Boolean { value },
            RawResolutionValue::Integer { value } => Self::Integer { value },
            RawResolutionValue::Decimal { value } => Self::Decimal { value },
            RawResolutionValue::Text { value } => Self::Text { value },
            RawResolutionValue::Enum { value } => Self::Enum { value },
            RawResolutionValue::List { items } => Self::List { items },
            RawResolutionValue::Map { entries } => Self::Map { entries: entries.0 },
            RawResolutionValue::Object { fields } => Self::Object { fields: fields.0 },
            RawResolutionValue::CatalogRef {
                catalog_id,
                digest_sha256,
                entry_count,
                canonical_bytes,
            } => Self::CatalogRef {
                catalog_id,
                digest_sha256,
                entry_count,
                canonical_bytes,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredValue {
    pub family: String,
    pub source: SourceKind,
    pub evidence_digest_sha256: String,
    pub value: ResolutionValue,
}

/// A profile is only a bounded container for an existing declared source. It is not a new
/// precedence layer and cannot impersonate CLI, environment, built-in, runtime, or provider facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileValue {
    pub family: String,
    pub as_declared_source: SourceKind,
    pub value: ResolutionValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionProfile {
    pub schema_version: u16,
    pub profile_id: String,
    pub registry_revision: u16,
    pub registry_digest: String,
    pub values: Vec<ProfileValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceSubject {
    Global,
    Operator {
        authority_digest_sha256: String,
    },
    Route {
        route: RouteIdentity,
    },
    RuntimeSeam {
        seam: String,
        subject_digest_sha256: String,
    },
    Catalog {
        catalog_id: String,
        digest_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceState {
    Present { value: ResolutionValue },
    Absent { code: String },
    Unsupported { code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultEvidence {
    pub family: String,
    pub resolver_id: String,
    pub subject: EvidenceSubject,
    pub evidence_digest_sha256: String,
    pub state: EvidenceState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationEvidence {
    /// Canonical registry family identity. The seam alone is not an activation identity because
    /// multiple families may be implemented at the same runtime location.
    pub family: String,
    pub seam: String,
    pub subject_digest_sha256: String,
    pub evidence_digest_sha256: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteIdentity {
    pub provider_id: String,
    pub model_id: String,
    pub route_revision: String,
    pub catalog_digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCapabilities {
    pub route: RouteIdentity,
    pub capabilities: BTreeSet<CapabilityRequirement>,
    pub attestation_digest_sha256: String,
}

/// Evidence provides an attested bound/domain only. The registry rule—not this request—chooses the
/// comparison, violation action, and any degrade policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConstraintValue {
    UpperBound {
        value: ResolutionValue,
    },
    Exact {
        value: ResolutionValue,
    },
    Domain {
        minimum: Option<ResolutionValue>,
        maximum: Option<ResolutionValue>,
        allowed_values: Option<BTreeSet<ResolutionValue>>,
        required_values: Option<BTreeSet<ResolutionValue>>,
        preferred: Option<ResolutionValue>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintEvidence {
    pub family: String,
    pub field: String,
    pub ceiling: ExternalCeiling,
    pub subject: EvidenceSubject,
    pub evidence_digest_sha256: String,
    pub value: ConstraintValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSnapshot {
    pub catalog_id: String,
    pub digest_sha256: String,
    pub values: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContext {
    #[serde(default)]
    pub admitted_routes: Vec<RouteCapabilities>,
    #[serde(default)]
    pub selected_route: Option<RouteIdentity>,
    #[serde(default)]
    pub catalogs: Vec<CatalogSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionInput {
    pub schema_version: u16,
    pub registry_id: String,
    pub registry_revision: u16,
    pub registry_digest: String,
    #[serde(default)]
    pub profile: Option<ResolutionProfile>,
    #[serde(default)]
    pub declared_values: Vec<DeclaredValue>,
    #[serde(default)]
    pub default_evidence: Vec<DefaultEvidence>,
    #[serde(default)]
    pub activation_evidence: Vec<ActivationEvidence>,
    #[serde(default)]
    pub constraint_evidence: Vec<ConstraintEvidence>,
    #[serde(default)]
    pub runtime: RuntimeContext,
}
