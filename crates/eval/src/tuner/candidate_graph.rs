use super::{
    CandidateImplementation, MAX_UNIVERSAL_CANDIDATE_DIMENSIONS, TunerCandidate, TunerError,
};
use iteron_tunables::{
    ArtifactOverride, ParamAssignment, ProfileDocument, ProfileValue, ResolutionValue, SourceKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const CANDIDATE_GRAPH_SCHEMA_ID: &str = "iteron-candidate/3";
pub const CANDIDATE_GRAPH_SCHEMA_VERSION: u16 = 3;
pub const MAX_CANDIDATE_TOPOLOGY_EDGES: usize = 16_384;
const MAX_ADDRESS_TEXT_BYTES: usize = 4_096;
const MAX_NATIVE_VALUE_BYTES: usize = 64 * 1024;
const MAX_VALUE_DEPTH: usize = 16;
const MAX_VALUE_NODES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateAddressKind {
    UnifiedProfile,
    DirectConfig,
    CallerInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSelectorKind {
    Key,
    Path,
    Argument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateOwnerKind {
    Schema,
    Protocol,
}

/// Stable language-neutral address copied from the optimization census.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateAddress {
    pub kind: CandidateAddressKind,
    pub selector_kind: CandidateSelectorKind,
    pub selector: String,
    pub owner_kind: CandidateOwnerKind,
    pub owner: String,
}

impl CandidateAddress {
    pub fn validate(&self) -> Result<(), TunerError> {
        bounded_text(&self.selector, "candidate selector")?;
        bounded_text(&self.owner, "candidate owner")?;
        let compatible = matches!(
            (self.kind, self.selector_kind, self.owner_kind),
            (
                CandidateAddressKind::UnifiedProfile,
                CandidateSelectorKind::Key,
                CandidateOwnerKind::Schema
            ) | (
                CandidateAddressKind::DirectConfig,
                CandidateSelectorKind::Path,
                CandidateOwnerKind::Schema | CandidateOwnerKind::Protocol
            ) | (
                CandidateAddressKind::DirectConfig,
                CandidateSelectorKind::Argument,
                CandidateOwnerKind::Schema
            ) | (
                CandidateAddressKind::CallerInput,
                CandidateSelectorKind::Argument,
                CandidateOwnerKind::Protocol
            )
        );
        if !compatible {
            return Err(invalid("candidate address kinds are incompatible"));
        }
        Ok(())
    }
}

/// One resolved dimension. The tagged variants prevent native patches from being confused with
/// profile families, parameters, or model-visible text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "dimension_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateDimension {
    Family {
        address: CandidateAddress,
        family: String,
        as_declared_source: SourceKind,
        value: ResolutionValue,
    },
    Param {
        address: CandidateAddress,
        param: String,
        value: ResolutionValue,
    },
    Artifact {
        address: CandidateAddress,
        artifact: String,
        text: String,
    },
    NativeValue {
        address: CandidateAddress,
        value: ResolutionValue,
    },
}

impl CandidateDimension {
    pub fn address(&self) -> &CandidateAddress {
        match self {
            Self::Family { address, .. }
            | Self::Param { address, .. }
            | Self::Artifact { address, .. }
            | Self::NativeValue { address, .. } => address,
        }
    }

    fn value(&self) -> Option<&ResolutionValue> {
        match self {
            Self::Family { value, .. }
            | Self::Param { value, .. }
            | Self::NativeValue { value, .. } => Some(value),
            Self::Artifact { .. } => None,
        }
    }

    fn validate(&self) -> Result<(), TunerError> {
        let address = self.address();
        address.validate()?;
        match self {
            Self::Family {
                family,
                value,
                address,
                ..
            } => {
                profile_address(address, family, "family")?;
                validate_value(value)?;
            }
            Self::Param {
                param,
                value,
                address,
            } => {
                profile_address(address, param, "param")?;
                validate_value(value)?;
            }
            Self::Artifact {
                artifact,
                text,
                address,
            } => {
                profile_address(address, artifact, "artifact")?;
                if text.is_empty() || text.len() > iteron_tunables::MAX_ARTIFACT_TEXT_BYTES {
                    return Err(invalid("candidate artifact text is outside its bound"));
                }
            }
            Self::NativeValue { address, value } => {
                if address.kind == CandidateAddressKind::UnifiedProfile {
                    return Err(invalid("native values cannot target the unified profile"));
                }
                validate_value(value)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateLineage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_sha256: Option<String>,
    pub generation: u32,
    /// Exact sorted addresses changed from the parent. A root has no sparse delta.
    #[serde(default)]
    pub sparse_delta: Vec<CandidateAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateExperiment {
    pub dataset_sha256: String,
    pub evaluator_sha256: String,
    pub environment_sha256: String,
    pub resource_sha256: String,
    pub fidelity_sha256: String,
    pub seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCondition {
    pub address: CandidateAddress,
    pub equals: ResolutionValue,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateTopologyEdge {
    pub dependency: CandidateAddress,
    pub dependent: CandidateAddress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<CandidateCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateGraph {
    pub schema_id: String,
    pub dimensions: Vec<CandidateDimension>,
    pub lineage: CandidateLineage,
    pub experiment: CandidateExperiment,
    #[serde(default)]
    pub topology: Vec<CandidateTopologyEdge>,
    #[serde(default)]
    pub implementations: Vec<CandidateImplementation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePatch {
    pub address: CandidateAddress,
    pub value: ResolutionValue,
}

/// Runtime class of one production-plan node. This is carried beside the full dimension rather
/// than standing in for it: an adapter must receive and apply the value-bearing dimension, not
/// merely acknowledge an address or digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateNodeClass {
    UnifiedProfile,
    DirectConfig,
    CallerInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateExecutionDependency {
    pub address: CandidateAddress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<CandidateCondition>,
}

/// One value-bearing node in the exact order in which production composition must apply it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateExecutionNode {
    pub ordinal: u32,
    pub class: CandidateNodeClass,
    pub dimension: CandidateDimension,
    #[serde(default)]
    pub dependencies: Vec<CandidateExecutionDependency>,
}

/// Closed production plan consumed by the combined native adapter. Implementation bindings are
/// part of the same plan and the same terminal receipt, even though graph edges address value
/// dimensions (implementation lifecycle dependencies remain marketplace-owned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProductionPlan {
    pub nodes: Vec<CandidateExecutionNode>,
    pub implementations: Vec<CandidateImplementation>,
}

/// Every accepted v3 dimension occurs exactly once in one of these outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateMaterialization {
    pub profile: ProfileDocument,
    /// Exact value-bearing graph nodes retained for production ordering and consumption receipts.
    pub dimensions: Vec<CandidateDimension>,
    pub direct_config_patches: Vec<CandidatePatch>,
    pub caller_input_patches: Vec<CandidatePatch>,
    pub implementations: Vec<CandidateImplementation>,
    pub topology: Vec<CandidateTopologyEdge>,
    pub lineage: CandidateLineage,
    pub experiment: CandidateExperiment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateGraphIdentity {
    pub schema_id: String,
    pub materialization_sha256: String,
    pub experiment_sha256: String,
    pub topology_sha256: String,
}

impl CandidateGraph {
    pub fn validate(&self, candidate: &TunerCandidate) -> Result<(), TunerError> {
        if self.schema_id != CANDIDATE_GRAPH_SCHEMA_ID
            || self
                .dimensions
                .len()
                .saturating_add(self.implementations.len())
                == 0
            || self
                .dimensions
                .len()
                .saturating_add(self.implementations.len())
                > MAX_UNIVERSAL_CANDIDATE_DIMENSIONS
            || self.topology.len() > MAX_CANDIDATE_TOPOLOGY_EDGES
        {
            return Err(invalid("candidate graph schema or width is invalid"));
        }
        let mut prior_address: Option<&CandidateAddress> = None;
        let mut values = BTreeMap::new();
        for dimension in &self.dimensions {
            dimension.validate()?;
            let address = dimension.address();
            if prior_address.is_some_and(|prior| prior >= address) {
                return Err(invalid(
                    "candidate dimensions must have unique sorted addresses",
                ));
            }
            prior_address = Some(address);
            values.insert(address.clone(), dimension.value());
        }
        validate_lineage(&self.lineage, &values, candidate)?;
        validate_experiment(&self.experiment)?;
        validate_implementations(&self.implementations)?;
        validate_topology(&self.topology, &values)?;
        Ok(())
    }

    pub fn materialize(
        &self,
        candidate: &TunerCandidate,
    ) -> Result<CandidateMaterialization, TunerError> {
        self.validate(candidate)?;
        let mut profile = ProfileDocument {
            schema_version: iteron_tunables::PROFILE_DOCUMENT_SCHEMA_VERSION,
            profile_id: candidate.id.clone(),
            registry_revision: iteron_tunables::REGISTRY_REVISION,
            registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
            param_registry_digest: Some(iteron_tunables::param_registry_digest_sha256()),
            module_scope: None,
            values: Vec::new(),
            params: Vec::new(),
            artifacts: Vec::new(),
        };
        let mut direct_config_patches = Vec::new();
        let mut caller_input_patches = Vec::new();
        for dimension in &self.dimensions {
            match dimension {
                CandidateDimension::Family {
                    family,
                    as_declared_source,
                    value,
                    ..
                } => profile.values.push(ProfileValue {
                    family: family.clone(),
                    as_declared_source: *as_declared_source,
                    value: value.clone(),
                }),
                CandidateDimension::Param { param, value, .. } => {
                    profile.params.push(ParamAssignment {
                        param: param.clone(),
                        value: value.clone(),
                    });
                }
                CandidateDimension::Artifact { artifact, text, .. } => {
                    profile.artifacts.push(ArtifactOverride {
                        artifact: artifact.clone(),
                        text: text.clone(),
                    });
                }
                CandidateDimension::NativeValue { address, value } => {
                    let patch = CandidatePatch {
                        address: address.clone(),
                        value: value.clone(),
                    };
                    match address.kind {
                        CandidateAddressKind::DirectConfig => direct_config_patches.push(patch),
                        CandidateAddressKind::CallerInput => caller_input_patches.push(patch),
                        CandidateAddressKind::UnifiedProfile => unreachable!("validated above"),
                    }
                }
            }
        }
        iteron_tunables::validate_profile(&profile).map_err(|error| invalid(&error.to_string()))?;
        Ok(CandidateMaterialization {
            profile,
            dimensions: self.dimensions.clone(),
            direct_config_patches,
            caller_input_patches,
            implementations: self.implementations.clone(),
            topology: self.topology.clone(),
            lineage: self.lineage.clone(),
            experiment: self.experiment.clone(),
        })
    }
}

impl CandidateMaterialization {
    pub fn digest_sha256(&self) -> Result<String, TunerError> {
        canonical_digest(self)
    }

    pub fn graph_identity(&self) -> Result<CandidateGraphIdentity, TunerError> {
        Ok(CandidateGraphIdentity {
            schema_id: CANDIDATE_GRAPH_SCHEMA_ID.into(),
            materialization_sha256: self.digest_sha256()?,
            experiment_sha256: canonical_digest(&self.experiment)?,
            topology_sha256: canonical_digest(&self.topology)?,
        })
    }

    pub fn has_native_patches(&self) -> bool {
        !self.direct_config_patches.is_empty() || !self.caller_input_patches.is_empty()
    }

    /// Resolve the validated topology into one deterministic production order. Conditions are
    /// retained on the dependent node so the production adapter must evaluate them before apply.
    /// A second fail-closed graph check here prevents a deserialized/materialized value from ever
    /// being treated as an executable plan solely because its topology digest was accepted.
    pub fn production_plan(&self) -> Result<CandidateProductionPlan, TunerError> {
        production_plan_from_dimensions(&self.dimensions, &self.topology, &self.implementations)
    }
}

fn production_plan_from_dimensions(
    dimensions: &[CandidateDimension],
    topology: &[CandidateTopologyEdge],
    implementations: &[CandidateImplementation],
) -> Result<CandidateProductionPlan, TunerError> {
    let mut by_address = BTreeMap::new();
    let mut values = BTreeMap::new();
    for dimension in dimensions {
        dimension.validate()?;
        if by_address
            .insert(dimension.address().clone(), dimension.clone())
            .is_some()
        {
            return Err(invalid("production plan contains a duplicate node"));
        }
        values.insert(dimension.address().clone(), dimension.value());
    }
    validate_implementations(implementations)?;
    validate_topology(topology, &values)?;

    let mut indegree = by_address
        .keys()
        .cloned()
        .map(|address| (address, 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut outgoing = BTreeMap::<CandidateAddress, Vec<CandidateAddress>>::new();
    let mut dependencies = BTreeMap::<CandidateAddress, Vec<CandidateExecutionDependency>>::new();
    for edge in topology {
        *indegree
            .get_mut(&edge.dependent)
            .ok_or_else(|| invalid("production topology names a missing dependent node"))? += 1;
        outgoing
            .entry(edge.dependency.clone())
            .or_default()
            .push(edge.dependent.clone());
        dependencies
            .entry(edge.dependent.clone())
            .or_default()
            .push(CandidateExecutionDependency {
                address: edge.dependency.clone(),
                condition: edge.condition.clone(),
            });
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(address, degree)| (*degree == 0).then_some(address.clone()))
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(by_address.len());
    while let Some(address) = ready.pop_first() {
        let dimension = by_address
            .get(&address)
            .cloned()
            .ok_or_else(|| invalid("production topology lost a node"))?;
        let class = match address.kind {
            CandidateAddressKind::UnifiedProfile => CandidateNodeClass::UnifiedProfile,
            CandidateAddressKind::DirectConfig => CandidateNodeClass::DirectConfig,
            CandidateAddressKind::CallerInput => CandidateNodeClass::CallerInput,
        };
        ordered.push(CandidateExecutionNode {
            ordinal: ordered
                .len()
                .try_into()
                .map_err(|_| invalid("production topology ordinal overflow"))?,
            class,
            dimension,
            dependencies: dependencies.remove(&address).unwrap_or_default(),
        });
        for dependent in outgoing.get(&address).into_iter().flatten() {
            let degree = indegree
                .get_mut(dependent)
                .ok_or_else(|| invalid("production topology names a missing node"))?;
            *degree = degree
                .checked_sub(1)
                .ok_or_else(|| invalid("production topology indegree underflow"))?;
            if *degree == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    if ordered.len() != by_address.len() {
        return Err(invalid("production topology contains a cycle"));
    }
    Ok(CandidateProductionPlan {
        nodes: ordered,
        implementations: implementations.to_vec(),
    })
}

fn profile_address(
    address: &CandidateAddress,
    expected_selector: &str,
    field: &str,
) -> Result<(), TunerError> {
    bounded_text(expected_selector, field)?;
    if address.kind != CandidateAddressKind::UnifiedProfile
        || address.selector_kind != CandidateSelectorKind::Key
        || address.owner_kind != CandidateOwnerKind::Schema
        || address.selector != expected_selector
    {
        return Err(invalid("profile dimension does not match its address"));
    }
    Ok(())
}

fn validate_lineage(
    lineage: &CandidateLineage,
    dimensions: &BTreeMap<CandidateAddress, Option<&ResolutionValue>>,
    candidate: &TunerCandidate,
) -> Result<(), TunerError> {
    let root = lineage.generation == 0;
    if root != lineage.parent_sha256.is_none()
        || (root && !lineage.sparse_delta.is_empty())
        || (!root && lineage.sparse_delta.is_empty())
        || lineage.sparse_delta.len() > dimensions.len()
    {
        return Err(invalid("candidate lineage shape is invalid"));
    }
    if let Some(parent) = &lineage.parent_sha256 {
        validate_digest(parent, "candidate parent digest")?;
        if parent == &super::state_ops::digest(candidate)? {
            return Err(invalid("candidate cannot name itself as its parent"));
        }
    }
    let mut prior: Option<&CandidateAddress> = None;
    for address in &lineage.sparse_delta {
        address.validate()?;
        if !dimensions.contains_key(address) || prior.is_some_and(|item| item >= address) {
            return Err(invalid(
                "candidate sparse delta is not a sorted graph subset",
            ));
        }
        prior = Some(address);
    }
    Ok(())
}

fn validate_experiment(experiment: &CandidateExperiment) -> Result<(), TunerError> {
    for (value, field) in [
        (&experiment.dataset_sha256, "dataset digest"),
        (&experiment.evaluator_sha256, "evaluator digest"),
        (&experiment.environment_sha256, "environment digest"),
        (&experiment.resource_sha256, "resource digest"),
        (&experiment.fidelity_sha256, "fidelity digest"),
    ] {
        validate_digest(value, field)?;
    }
    Ok(())
}

fn validate_implementations(implementations: &[CandidateImplementation]) -> Result<(), TunerError> {
    if implementations.len() > iteron_tunables::ModuleId::ALL.len() {
        return Err(invalid("implementation bindings exceed their module bound"));
    }
    let mut prior: Option<(iteron_tunables::ModuleId, &str)> = None;
    let mut modules = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for implementation in implementations {
        super::state_ops::validate_implementation_binding(implementation, None)?;
        let identity = (
            implementation.module,
            implementation.implementation_id.as_str(),
        );
        if prior.is_some_and(|item| item >= identity)
            || !modules.insert(implementation.module)
            || !ids.insert(implementation.implementation_id.as_str())
        {
            return Err(invalid("implementation bindings must be unique and sorted"));
        }
        prior = Some(identity);
    }
    Ok(())
}

fn validate_topology(
    topology: &[CandidateTopologyEdge],
    dimensions: &BTreeMap<CandidateAddress, Option<&ResolutionValue>>,
) -> Result<(), TunerError> {
    let mut prior: Option<&CandidateTopologyEdge> = None;
    let mut indegree = BTreeMap::<CandidateAddress, usize>::new();
    let mut outgoing = BTreeMap::<CandidateAddress, Vec<CandidateAddress>>::new();
    for address in dimensions.keys() {
        indegree.insert(address.clone(), 0);
    }
    for edge in topology {
        edge.dependency.validate()?;
        edge.dependent.validate()?;
        if edge.dependency == edge.dependent
            || !dimensions.contains_key(&edge.dependency)
            || !dimensions.contains_key(&edge.dependent)
            || prior.is_some_and(|item| item >= edge)
        {
            return Err(invalid("candidate topology is not a unique sorted graph"));
        }
        if let Some(condition) = &edge.condition {
            condition.address.validate()?;
            validate_value(&condition.equals)?;
            if dimensions.get(&condition.address).copied().flatten() != Some(&condition.equals) {
                return Err(invalid("candidate conditional dependency is not satisfied"));
            }
        }
        *indegree.get_mut(&edge.dependent).expect("checked above") += 1;
        outgoing
            .entry(edge.dependency.clone())
            .or_default()
            .push(edge.dependent.clone());
        prior = Some(edge);
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(address, degree)| (*degree == 0).then_some(address.clone()))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(address) = ready.pop_front() {
        visited += 1;
        for dependent in outgoing.get(&address).into_iter().flatten() {
            let degree = indegree.get_mut(dependent).expect("checked above");
            *degree -= 1;
            if *degree == 0 {
                ready.push_back(dependent.clone());
            }
        }
    }
    if visited != dimensions.len() {
        return Err(invalid("candidate topology contains a cycle"));
    }
    Ok(())
}

fn validate_value(value: &ResolutionValue) -> Result<(), TunerError> {
    let bytes = serde_json::to_vec(value).map_err(|error| TunerError::Encode(error.to_string()))?;
    let mut nodes = 0_usize;
    if bytes.len() > MAX_NATIVE_VALUE_BYTES || !bounded_value(value, 0, &mut nodes) {
        return Err(invalid("candidate value exceeds its structural bound"));
    }
    Ok(())
}

fn bounded_value(value: &ResolutionValue, depth: usize, nodes: &mut usize) -> bool {
    *nodes = nodes.saturating_add(1);
    if depth > MAX_VALUE_DEPTH || *nodes > MAX_VALUE_NODES {
        return false;
    }
    match value {
        ResolutionValue::Text { value } | ResolutionValue::Enum { value } => {
            value.len() <= MAX_ADDRESS_TEXT_BYTES && !value.contains('\0')
        }
        ResolutionValue::List { items } => items
            .iter()
            .all(|item| bounded_value(item, depth + 1, nodes)),
        ResolutionValue::Map { entries } | ResolutionValue::Object { fields: entries } => {
            entries.len() <= MAX_VALUE_NODES
                && entries.iter().all(|(key, value)| {
                    !key.is_empty()
                        && key.len() <= MAX_ADDRESS_TEXT_BYTES
                        && !key.contains('\0')
                        && bounded_value(value, depth + 1, nodes)
                })
        }
        ResolutionValue::CatalogRef {
            catalog_id,
            digest_sha256,
            entry_count,
            canonical_bytes,
        } => {
            !catalog_id.is_empty()
                && catalog_id.len() <= MAX_ADDRESS_TEXT_BYTES
                && validate_digest(digest_sha256, "catalog digest").is_ok()
                && *entry_count <= 1_000_000
                && *canonical_bytes <= 1024 * 1024 * 1024
        }
        ResolutionValue::Boolean { .. }
        | ResolutionValue::Integer { .. }
        | ResolutionValue::Decimal { .. } => true,
    }
}

fn bounded_text(value: &str, field: &str) -> Result<(), TunerError> {
    if value.is_empty()
        || value.len() > MAX_ADDRESS_TEXT_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(invalid(&format!("{field} is outside its bound")));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> Result<(), TunerError> {
    if !super::state_ops::valid_digest(value) {
        return Err(invalid(&format!("{field} is invalid")));
    }
    Ok(())
}

fn canonical_digest(value: &impl Serialize) -> Result<String, TunerError> {
    let bytes = serde_json::to_vec(value).map_err(|error| TunerError::Encode(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn invalid(message: &str) -> TunerError {
    TunerError::InvalidSpec(message.into())
}
