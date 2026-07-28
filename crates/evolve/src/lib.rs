//! Bounded contracts and non-authoritative assessors for a future Core evolution control plane.
//!
//! This crate is intentionally **outside** the runtime trusted computing base. It cannot load a
//! policy, grant a capability, execute a tool, or hot-swap a running agent. Its append-only
//! registries retain offline evidence. [`PromotionGate::assess`] remains non-authoritative advice;
//! the separate [`PromotionAuthority`] can only advance an authenticated, fixed-policy offline
//! release record and active-bundle pointer. It has no runtime registry handle or loader, so
//! adaptive runtime activation remains explicitly **NO-GO**.
//!
//! The contracts are method-agnostic: hand-authored rules, search, contextual bandits, SFT,
//! preference optimization, GRPO, offline RL, online RL, LoRA/adapters, and generated policy code
//! may eventually produce the same versioned [`PolicyManifest`]. For now, these types support
//! recording, offline validation, and assessment only.

use core_protocol::Capability;
use core_protocol::bundle::{ResolvedBundle, ResolvedPolicy};
use core_protocol::slot::SlotId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod admission;
mod base_model;
mod dataset;
mod dataset_registry;
mod evidence;
mod producer;
mod promotion;
mod promotion_auth;
mod promotion_authority;
mod promotion_authority_verify;
mod promotion_evaluation;
mod promotion_journal;
mod promotion_state;
mod registry;
mod schema;
mod seams;
mod training;
mod verifier;
mod verifier_crypto;
mod verifier_eval;

#[cfg(test)]
mod verifier_tests;

pub use admission::{
    CapabilityAdmission, CapabilityAdmissionError, EffectiveCapabilities, ManifestAdmissionPolicy,
    ParentCapabilityCeiling,
};
pub use base_model::{BaseModelId, MAX_BASE_MODEL_PART_BYTES, UNSPECIFIED_FAMILY};
/// Re-exported so an outside implementor of [`TrajectoryProjection`] can construct the
/// [`TrajectoryEnvelope`] it must return without taking a second, undeclared dependency on
/// `core-protocol`. Without these the seam was unimplementable from outside the crate (E0603).
pub use core_protocol::{RunId, TenantId};
pub use dataset::{
    GovernedDatasetError, GovernedTrainingDataset, MAX_GOVERNED_DATASET_BYTES,
    MAX_GOVERNED_DATASET_TRAJECTORIES,
};
pub use dataset_registry::{
    ConsentAwareDatasetRegistry, DatasetAuditEvent, DatasetAuditKind, DatasetMemberIdentity,
    DatasetRegistration, DatasetRegistryError, MAX_DATASET_AUDIT_EVENTS, MAX_DATASET_REVOCATIONS,
    MAX_REGISTERED_DATASETS,
};
pub use evidence::{EvidenceRecordError, EvidenceRecorder};
pub use producer::{
    MAX_INERT_RULE_ARTIFACT_BYTES, MAX_OFFLINE_RULE_CANDIDATES, OfflineProducerError,
    OfflineRuleCandidate, OfflineRuleSearchProducer, OfflineRuleSearchSpec,
    ProducedPolicyCandidate,
};
pub use promotion::{
    DeploymentBundle, EvaluatorTrustAnchor, MAX_DEPLOYMENT_BUNDLE_BYTES,
    MAX_EVALUATOR_TRUST_ANCHORS, MAX_PROMOTION_AUDIT_EVENTS, MAX_PROMOTION_AUTH_BYTES,
    MAX_PROMOTION_CANDIDATES, MAX_PROMOTION_KEY_BYTES, MAX_PROMOTION_TRUST_ANCHORS,
    PromotionAuthorityError, PromotionAuthorityKey, PromotionControlPolicy, PromotionRole,
    PromotionTrustAnchor, StageLimits,
};
pub use promotion_auth::{
    PromotionAuthorization, PromotionAuthorizer, PromotionOperation, PromotionRequest,
};
pub use promotion_authority::PromotionAuthority;
pub use promotion_evaluation::{
    BoundedStageExecutor, HeldOutEvaluation, IndependentEvaluator, SignedHeldOutEvaluation,
    SignedStageObservation, StageObservation, StagePermit,
};
pub use promotion_state::{PromotionAuditEvent, PromotionAuditKind, PromotionLineage};
pub use registry::{
    BundleLineage, MAX_TRAJECTORY_LINEAGE_POLICIES, MAX_TRAJECTORY_REGISTRY_BYTES,
    MAX_TRAJECTORY_REGISTRY_ENVELOPE_BYTES, MAX_TRAJECTORY_REGISTRY_RECORD_BYTES,
    MAX_TRAJECTORY_REGISTRY_RECORDS, RegisteredTrajectory, TrajectoryAddress, TrajectoryIngest,
    TrajectoryLineage, TrajectoryRegistry, TrajectoryRegistryError,
};
pub use schema::{
    EVOLUTION_PREVIOUS_SCHEMA_VERSION, EvolutionDocumentKind, EvolutionLoadError,
    MAX_POLICY_MANIFEST_JSON_BYTES, MAX_TRAJECTORY_JSON_BYTES,
};
pub use seams::{HeldOutEvidenceBridge, TrajectoryProjection};
pub use training::{
    MAX_RETENTION_POLICY_TABLE_ENTRIES, MAX_TRAINING_LICENSE_ALLOWLIST_ENTRIES,
    RetentionTrainingUse, TrainingAdmissionPolicy, TrainingEligibilityError,
    TrainingEligibleTrajectory,
};
pub use verifier::{
    AttestationKey, EvolutionVerifier, MAX_ATTESTATION_KEY_BYTES, MAX_TRUSTED_PRODUCERS,
    MAX_VERIFIED_ARTIFACT_BYTES, ProducerTrustAnchor, SignedTrajectory, VerifiedCandidateInputs,
    VerifiedTrainingDataset, VerifiedTrajectory, VerifierError,
};
pub use verifier_eval::{EvaluationSuite, EvaluationTask, MAX_EVALUATION_TASKS};

#[cfg(test)]
mod promotion_tests;

pub const EVOLUTION_SCHEMA_VERSION: u16 = 3;

/// Contract bounds are defense in depth after a bounded transport/deserializer. They do not make
/// it safe to deserialize an arbitrarily large request into memory first.
pub const MAX_SHORT_STRING_BYTES: usize = 256;
pub const MAX_ARTIFACT_LOCATOR_BYTES: usize = 2_048;
pub const MAX_POLICIES_PER_BUNDLE: usize = 128;
pub const MAX_DECISIONS_PER_TRAJECTORY: usize = 4_096;
pub const MAX_DOMAIN_REWARDS: usize = 128;
pub const MAX_INVARIANT_SUITES: usize = 128;
pub const MAX_REQUIRED_CAPABILITIES: usize = 128;
pub const MAX_ACTION_JSON_DEPTH: usize = 32;
pub const MAX_ACTION_JSON_NODES: usize = 4_096;
pub const MAX_ACTION_JSON_BYTES: usize = 128 * 1_024;

/// A namespaced, swappable decision point. Slots are strings rather than a closed enum so a
/// vertical pack can add `db/query_planner` or `support/escalation_router` without changing the
/// microkernel. The well-known core slots below form the cross-vertical baseline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StrategySlot(String);

impl StrategySlot {
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'/' | b'_' | b'-' | b'.')
            })
            && !value.starts_with('/')
            && !value.ends_with('/')
            && !value.contains("//");
        if !valid {
            return Err(ContractError::InvalidSlot);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn router() -> Self {
        Self("core/router".into())
    }
    pub fn planner() -> Self {
        Self("core/planner".into())
    }
    pub fn context() -> Self {
        Self("core/context".into())
    }
    pub fn memory() -> Self {
        Self("core/memory".into())
    }
    pub fn scheduler() -> Self {
        Self("core/scheduler".into())
    }
    pub fn tool_policy() -> Self {
        Self("core/tool_policy".into())
    }
    pub fn verifier() -> Self {
        Self("core/verifier".into())
    }
    pub fn model_router() -> Self {
        Self("core/model_router".into())
    }
    pub fn collaboration() -> Self {
        Self("core/collaboration".into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("invalid strategy slot; use a bounded lowercase namespaced identifier")]
    InvalidSlot,
    #[error("invalid content digest; expected 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("invalid base model identity: {0}")]
    InvalidBaseModel(&'static str),
    #[error("{0}")]
    UnrecognisedVocabulary(&'static str),
    #[error("policy manifest schema {0} is not supported")]
    UnsupportedSchema(u16),
    #[error("policy id and version must be non-empty")]
    MissingIdentity,
    #[error("policy artifact locator must be non-empty")]
    MissingArtifactLocator,
    #[error("data-derived policy method {0:?} requires an optimization/training dataset digest")]
    MissingTrainingDataset(EvolutionMethod),
    #[error("policy bundle id must be non-empty and contain at least one policy")]
    InvalidBundleIdentity,
    #[error("protocol compatibility range is inverted")]
    InvertedProtocolRange,
    #[error("policy bundle contains duplicate slot `{0}`")]
    DuplicateSlot(String),
    #[error("decision does not refer to the policy active for slot `{0}`")]
    PolicySetMismatch(String),
    #[error("invalid propensity {0}; expected a finite value in (0, 1]")]
    InvalidPropensity(f64),
    #[error("reward contains a non-finite value")]
    NonFiniteReward,
    #[error("{field} must not be empty")]
    MissingField { field: &'static str },
    #[error("{field} is {actual} bytes; limit is {limit}")]
    StringTooLong {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("{field} contains {actual} entries; limit is {limit}")]
    CollectionTooLarge {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("action JSON depth exceeds {limit}")]
    ActionJsonTooDeep { limit: usize },
    #[error("action JSON contains more than {limit} nodes")]
    ActionJsonTooManyNodes { limit: usize },
    #[error("action JSON logical size exceeds {limit} bytes")]
    ActionJsonTooLarge { limit: usize },
    #[error("promotion assessor configuration is invalid: {0}")]
    InvalidPromotionGate(&'static str),
    #[error("promotion evidence contains a non-finite or malformed metric interval")]
    MalformedMetricInterval,
}

fn validate_digest(value: &str) -> Result<(), ContractError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ContractError::InvalidDigest)
    }
}

fn validate_nonempty_string(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::MissingField { field });
    }
    validate_string(field, value, limit)
}

fn validate_string(field: &'static str, value: &str, limit: usize) -> Result<(), ContractError> {
    if value.len() > limit {
        return Err(ContractError::StringTooLong {
            field,
            limit,
            actual: value.len(),
        });
    }
    Ok(())
}

fn validate_collection(
    field: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), ContractError> {
    if actual > limit {
        return Err(ContractError::CollectionTooLarge {
            field,
            limit,
            actual,
        });
    }
    Ok(())
}

fn add_action_size(total: &mut usize, amount: usize) -> Result<(), ContractError> {
    *total = total.saturating_add(amount);
    if *total > MAX_ACTION_JSON_BYTES {
        Err(ContractError::ActionJsonTooLarge {
            limit: MAX_ACTION_JSON_BYTES,
        })
    } else {
        Ok(())
    }
}

/// Iterative traversal avoids making attacker-selected JSON depth equal Rust call-stack depth.
/// String and key bytes are charged at their worst-case JSON escape expansion, yielding a
/// conservative serialized-size estimate. Contract validation does not recompute the action
/// digest; callers that need an authoritative content binding must cross [`EvidenceRecorder`].
fn validate_action_json(value: &serde_json::Value) -> Result<(), ContractError> {
    let mut pending = vec![(value, 1_usize)];
    let mut nodes = 0_usize;
    let mut logical_bytes = 0_usize;

    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_ACTION_JSON_DEPTH {
            return Err(ContractError::ActionJsonTooDeep {
                limit: MAX_ACTION_JSON_DEPTH,
            });
        }
        nodes = nodes.saturating_add(1);
        if nodes > MAX_ACTION_JSON_NODES {
            return Err(ContractError::ActionJsonTooManyNodes {
                limit: MAX_ACTION_JSON_NODES,
            });
        }

        match value {
            serde_json::Value::Null => add_action_size(&mut logical_bytes, 4)?,
            serde_json::Value::Bool(_) => add_action_size(&mut logical_bytes, 5)?,
            serde_json::Value::Number(_) => add_action_size(&mut logical_bytes, 32)?,
            serde_json::Value::String(value) => add_action_size(
                &mut logical_bytes,
                value.len().saturating_mul(6).saturating_add(2),
            )?,
            serde_json::Value::Array(values) => {
                add_action_size(&mut logical_bytes, values.len().saturating_add(2))?;
                if nodes
                    .saturating_add(pending.len())
                    .saturating_add(values.len())
                    > MAX_ACTION_JSON_NODES
                {
                    return Err(ContractError::ActionJsonTooManyNodes {
                        limit: MAX_ACTION_JSON_NODES,
                    });
                }
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            serde_json::Value::Object(values) => {
                add_action_size(&mut logical_bytes, values.len().saturating_add(2))?;
                if nodes
                    .saturating_add(pending.len())
                    .saturating_add(values.len())
                    > MAX_ACTION_JSON_NODES
                {
                    return Err(ContractError::ActionJsonTooManyNodes {
                        limit: MAX_ACTION_JSON_NODES,
                    });
                }
                for (key, value) in values {
                    add_action_size(
                        &mut logical_bytes,
                        key.len().saturating_mul(6).saturating_add(3),
                    )?;
                    pending.push((value, depth + 1));
                }
            }
        }
    }
    Ok(())
}

/// What kind of artifact implements a strategy. External artifacts are data or isolated
/// components; a manifest is never permission to load arbitrary native code into the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Rules,
    Prompt,
    WasmComponent,
    ModelAdapter,
    ModelWeights,
    ExternalService,
    /// Statically linked Rust implementation shipped with this exact Core build.
    Builtin,
    /// A kind this build does not recognise. Reached only by decoding a document written by a
    /// newer producer. Fail-closed: `PolicyManifest::validate` refuses it, so an unrecognised
    /// artifact is never loaded on the assumption that it resembles a known one.
    #[serde(other)]
    Unknown,
}

/// How the candidate was produced. Promotion semantics deliberately do not depend on this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionMethod {
    HandAuthored,
    Search,
    ContextualBandit,
    SupervisedFineTune,
    PreferenceOptimization,
    Grpo,
    OfflineRl,
    OnlineRl,
    GeneratedCode,
    /// A method this build does not recognise. Reached only by decoding a document written by a
    /// newer producer. Fail-closed: `PolicyManifest::validate` refuses it, because a manifest
    /// naming a method we cannot reason about has not been understood.
    ///
    /// Placed last because `serde` requires `#[serde(other)]` on the final variant.
    ///
    /// `DeploymentStage` is deliberately excluded from this sweep on different grounds - see its
    /// docs for the producer-vocabulary vs owned-state distinction that decides which enums get
    /// this treatment.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolRange {
    pub min: u16,
    pub max: u16,
}

/// Immutable identity of one strategy implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRef {
    pub slot: StrategySlot,
    pub policy_id: String,
    pub version: String,
    /// Digest of the artifact bytes, not a mutable URL.
    pub digest: String,
}

impl PolicyRef {
    pub fn validate(&self) -> Result<(), ContractError> {
        // Serde can construct the private newtype without going through `StrategySlot::new`, so
        // validate the namespace at every persisted contract boundary too.
        StrategySlot::new(self.slot.as_str())?;
        if self.policy_id.trim().is_empty() || self.version.trim().is_empty() {
            return Err(ContractError::MissingIdentity);
        }
        validate_string("policy.policy_id", &self.policy_id, MAX_SHORT_STRING_BYTES)?;
        validate_string("policy.version", &self.version, MAX_SHORT_STRING_BYTES)?;
        validate_digest(&self.digest)
    }
}

/// Claimed provenance and compatibility for a candidate. Dataset and eval digest fields are
/// mandatory for learned policies, but validation checks only their encoding. A future trusted
/// registry must recompute and attest the content and detect train/eval overlap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyManifest {
    pub schema_version: u16,
    pub policy: PolicyRef,
    pub artifact_kind: ArtifactKind,
    pub artifact_locator: String,
    pub parent: Option<PolicyRef>,
    pub method: EvolutionMethod,
    pub protocol: ProtocolRange,
    pub required_capabilities: BTreeSet<Capability>,
    pub training_dataset_digest: Option<String>,
    pub evaluation_suite_digest: String,
    /// Which frozen base model this policy was learned against.
    ///
    /// Required since schema 3. Documents migrated from schema 2 carry
    /// [`BaseModelId::unspecified`], which is well-formed but never admissible for an authority
    /// decision - schema 2 did not record the field, so there is nothing to recover.
    pub base_model: BaseModelId,
}

impl PolicyManifest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != EVOLUTION_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchema(self.schema_version));
        }
        self.policy.validate()?;
        if self.artifact_kind == ArtifactKind::Unknown {
            return Err(ContractError::UnrecognisedVocabulary(
                "artifact kind is unknown to this build",
            ));
        }
        if self.method == EvolutionMethod::Unknown {
            return Err(ContractError::UnrecognisedVocabulary(
                "evolution method is unknown to this build",
            ));
        }
        self.base_model.validate()?;
        if self.artifact_locator.trim().is_empty() {
            return Err(ContractError::MissingArtifactLocator);
        }
        validate_string(
            "policy_manifest.artifact_locator",
            &self.artifact_locator,
            MAX_ARTIFACT_LOCATOR_BYTES,
        )?;
        if self.protocol.min > self.protocol.max {
            return Err(ContractError::InvertedProtocolRange);
        }
        validate_collection(
            "policy_manifest.required_capabilities",
            self.required_capabilities.len(),
            MAX_REQUIRED_CAPABILITIES,
        )?;
        if self.method.requires_training_data() && self.training_dataset_digest.is_none() {
            return Err(ContractError::MissingTrainingDataset(self.method));
        }
        if let Some(digest) = &self.training_dataset_digest {
            validate_digest(digest)?;
        }
        validate_digest(&self.evaluation_suite_digest)?;
        if let Some(parent) = &self.parent {
            parent.validate()?;
        }
        Ok(())
    }
}

impl EvolutionMethod {
    fn requires_training_data(self) -> bool {
        // Search, bandits and generated code can leak or overfit their optimization corpus just as
        // gradient-based methods can. Represent a genuinely data-free candidate as HandAuthored;
        // every data-derived method must pin the exact governed input set.
        !matches!(self, Self::HandAuthored)
    }
}

/// Contract for an immutable strategy set that a future runtime may resolve at run admission.
/// This crate neither resolves nor activates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub bundle_id: String,
    pub digest: String,
    pub policies: Vec<PolicyRef>,
    pub rollback_to: Option<String>,
}

impl PolicyBundle {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.bundle_id.trim().is_empty() || self.policies.is_empty() {
            return Err(ContractError::InvalidBundleIdentity);
        }
        validate_string(
            "policy_bundle.bundle_id",
            &self.bundle_id,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_collection(
            "policy_bundle.policies",
            self.policies.len(),
            MAX_POLICIES_PER_BUNDLE,
        )?;
        if let Some(rollback_to) = &self.rollback_to {
            validate_nonempty_string(
                "policy_bundle.rollback_to",
                rollback_to,
                MAX_SHORT_STRING_BYTES,
            )?;
        }
        validate_digest(&self.digest)?;
        let mut slots = BTreeSet::new();
        for policy in &self.policies {
            policy.validate()?;
            if !slots.insert(policy.slot.clone()) {
                return Err(ContractError::DuplicateSlot(
                    policy.slot.as_str().to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn policy_for(&self, slot: &StrategySlot) -> Option<&PolicyRef> {
        self.policies.iter().find(|p| &p.slot == slot)
    }

    /// Project this bundle into the read-only view the runtime consumes.
    ///
    /// This is the producing half of the bundle-resolution seam. The port itself lives in
    /// `core-protocol` ([`core_protocol::bundle::PolicyBundleResolver`]) rather than here, because
    /// declaring it over this crate's types would force `crates/agents` to depend on `core-evolve`
    /// to name it — the exact edge the runtime must never grow. Both sides already depend on
    /// `core-protocol`, so projecting into its view costs neither side a dependency.
    ///
    /// # Fail-closed on the lossy direction
    ///
    /// [`StrategySlot`] and [`core_protocol::slot::SlotId`] are related by a strict-subset rule with
    /// a direction: every valid `SlotId` is a valid `StrategySlot`, but not the reverse — this side
    /// additionally accepts `.` and repeated `/`. So projecting can encounter a slot the kernel
    /// cannot name, and this refuses the whole bundle rather than dropping the entry. A dropped
    /// entry would leave that slot running its built-in strategy while the promotion journal
    /// recorded it as governed, which is a silent divergence between what ran and what the record
    /// says ran.
    pub fn resolve(&self) -> Result<ResolvedBundle, ContractError> {
        self.validate()?;
        let mut policies = Vec::with_capacity(self.policies.len());
        for policy in &self.policies {
            let slot = SlotId(policy.slot.as_str().to_owned());
            if slot.validate().is_err() {
                return Err(ContractError::InvalidSlot);
            }
            policies.push(ResolvedPolicy {
                slot,
                policy_id: policy.policy_id.clone(),
                version: policy.version.clone(),
                digest: policy.digest.clone(),
            });
        }
        let resolved = ResolvedBundle {
            bundle_id: self.bundle_id.clone(),
            digest: self.digest.clone(),
            policies,
        };
        // The view has its own bounds, and they are not this crate's to assume: re-validating here
        // means a bundle that is legal on the promotion side but unrepresentable on the runtime side
        // is refused at the projection, not discovered at the composition root.
        resolved
            .validate()
            .map_err(|_| ContractError::InvalidBundleIdentity)?;
        Ok(resolved)
    }
}

/// Contract for one learnable decision. Digest fields and propensity remain caller assertions
/// under [`StrategyDecision::validate`]. A trusted capture path must use [`EvidenceRecorder`] to
/// generate or verify `action_digest` from canonical action bytes before treating it as evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyDecision {
    pub decision_id: String,
    pub ordinal: u64,
    pub policy: PolicyRef,
    pub observation_digest: String,
    pub candidate_set_digest: String,
    pub action: serde_json::Value,
    pub action_digest: String,
    pub propensity: Option<f64>,
}

impl StrategyDecision {
    pub fn validate(&self, bundle: &PolicyBundle) -> Result<(), ContractError> {
        validate_nonempty_string(
            "strategy_decision.decision_id",
            &self.decision_id,
            MAX_SHORT_STRING_BYTES,
        )?;
        self.policy.validate()?;
        for digest in [
            &self.observation_digest,
            &self.candidate_set_digest,
            &self.action_digest,
        ] {
            validate_digest(digest)?;
        }
        if bundle.policy_for(&self.policy.slot) != Some(&self.policy) {
            return Err(ContractError::PolicySetMismatch(
                self.policy.slot.as_str().to_string(),
            ));
        }
        if let Some(p) = self.propensity
            && (!p.is_finite() || p <= 0.0 || p > 1.0)
        {
            return Err(ContractError::InvalidPropensity(p));
        }
        validate_action_json(&self.action)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Internal,
    CustomerConfidential,
    Personal,
    Secret,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingConsent {
    Allowed,
    EvaluationOnly,
    Denied,
}

/// Governance is part of the trajectory rather than an out-of-band promise. Runtime audit data
/// and training data are separate products: a run may be retained for compliance but ineligible
/// for learning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataGovernance {
    pub class: DataClass,
    pub consent: TrainingConsent,
    pub content_license: Option<String>,
    pub contains_secret_material: bool,
    pub retention_policy: String,
}

impl DataGovernance {
    pub fn validate(&self) -> Result<(), ContractError> {
        if let Some(content_license) = &self.content_license {
            validate_string(
                "data_governance.content_license",
                content_license,
                MAX_SHORT_STRING_BYTES,
            )?;
        }
        validate_nonempty_string(
            "data_governance.retention_policy",
            &self.retention_policy,
            MAX_SHORT_STRING_BYTES,
        )
    }
}

/// Multi-objective reward is retained as a vector. A trainer may declare a scalarization in its
/// own reproducible config, but safety and policy violations are hard constraints and may never
/// be traded for task score, latency, or cost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RewardVector {
    pub task_score: f64,
    pub correctness: f64,
    pub safety_violations: u32,
    pub policy_violations: u32,
    pub cost_usd: f64,
    pub wall_time_ms: u64,
    pub human_acceptance: Option<f64>,
    pub domain: BTreeMap<String, f64>,
}

impl RewardVector {
    pub fn validate(&self) -> Result<(), ContractError> {
        let scalars = [self.task_score, self.correctness, self.cost_usd];
        if scalars.iter().any(|v| !v.is_finite())
            || self.human_acceptance.is_some_and(|v| !v.is_finite())
            || self.domain.values().any(|v| !v.is_finite())
        {
            return Err(ContractError::NonFiniteReward);
        }
        validate_collection("reward.domain", self.domain.len(), MAX_DOMAIN_REWARDS)?;
        for key in self.domain.keys() {
            validate_nonempty_string("reward.domain key", key, MAX_SHORT_STRING_BYTES)?;
        }
        Ok(())
    }
}

/// Content-minimal training/evaluation projection of a run. It is not safe to aggregate merely
/// because it validates: tenant, governance, digests, and redaction status remain unauthenticated
/// assertions until a future evolution TCB verifies them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrajectoryEnvelope {
    pub schema_version: u16,
    pub run_id: RunId,
    pub tenant_id: TenantId,
    pub task_id: String,
    pub domain: String,
    pub environment_digest: String,
    pub bundle: PolicyBundle,
    pub decisions: Vec<StrategyDecision>,
    pub terminal_outcome: String,
    pub reward: RewardVector,
    pub governance: DataGovernance,
}

impl TrajectoryEnvelope {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != EVOLUTION_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchema(self.schema_version));
        }
        validate_nonempty_string("trajectory.run_id", &self.run_id.0, MAX_SHORT_STRING_BYTES)?;
        validate_nonempty_string(
            "trajectory.tenant_id",
            &self.tenant_id.0,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string("trajectory.task_id", &self.task_id, MAX_SHORT_STRING_BYTES)?;
        validate_nonempty_string("trajectory.domain", &self.domain, MAX_SHORT_STRING_BYTES)?;
        validate_nonempty_string(
            "trajectory.terminal_outcome",
            &self.terminal_outcome,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_collection(
            "trajectory.decisions",
            self.decisions.len(),
            MAX_DECISIONS_PER_TRAJECTORY,
        )?;
        validate_digest(&self.environment_digest)?;
        self.bundle.validate()?;
        self.reward.validate()?;
        self.governance.validate()?;
        for decision in &self.decisions {
            decision.validate(&self.bundle)?;
        }
        Ok(())
    }
}

/// EXEMPT from the `#[serde(other)] Unknown` sweep #26 asks for, deliberately.
///
/// The test that decides which enums get an `Unknown` variant is **who is allowed to extend the
/// vocabulary**, not whether the match sites happen to be safe:
///
/// - `ArtifactKind` and `EvolutionMethod` describe *what a producer made*. A newer producer is
///   entitled to invent a kind this build has never heard of, so a document naming one is
///   legitimately forward-compatible and must decode, then be refused on use.
/// - `DeploymentStage` describes *where this build's own promotion state machine has put a
///   candidate*. It is written and read by the same authority; there is no peer entitled to
///   extend it. A stage this build does not recognise is therefore not forward compatibility,
///   it is a corrupt or forged state record, and the correct response is a hard decode error
///   rather than a degrade to a sentinel that then has to be caught downstream.
///
/// A secondary reason to leave it alone: `serde` requires `#[serde(other)]` on the LAST variant
/// and this enum derives `Ord`, so an appended `Unknown` would sort above `Active`. Nothing
/// compares stages today - every match site is exhaustive or fail-closed on its wildcard
/// (`_ => true` meaning invalid, `_ => Err(StageMismatch)`, `_ => None`) - but that is a
/// property of the current call sites, not of the type, and a later `stage >= Canary` would
/// silently inherit the wrong answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStage {
    Candidate,
    Shadow,
    Canary,
    Active,
    Retired,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Interval {
    pub estimate: f64,
    pub lower: f64,
    pub upper: f64,
}

impl Interval {
    fn finite_and_ordered(self) -> bool {
        self.estimate.is_finite()
            && self.lower.is_finite()
            && self.upper.is_finite()
            && self.lower <= self.estimate
            && self.estimate <= self.upper
    }
}

/// Caller assertions about allegedly paired tasks, budgets, intervals, and invariant suites.
/// Nothing in this crate proves that the observations happened or came from an independent
/// evaluator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionEvidence {
    pub baseline: PolicyRef,
    pub candidate: PolicyRef,
    /// The frozen base model both sides of this comparison were measured on.
    ///
    /// A delta between a baseline and a candidate means nothing unless both were measured against
    /// the same weights, and this type is the *only* thing a reader of a stage observation gets:
    /// `StageObservation` carries a `PromotionEvidence` and nothing else that could name a model. An
    /// earlier version put the identity on `HeldOutEvaluation` alone, which attributed candidate
    /// admission correctly and left every separately-signed stage observation unable to say what it
    /// had been measured on. Issue #26 asked for both carriers; this is the shared field that gives
    /// them both one, rather than two fields that can disagree.
    ///
    /// `validate_contract` refuses the migration sentinel here, because evidence gathered against
    /// weights nobody recorded attests nothing about any particular model.
    pub base_model: BaseModelId,
    pub paired_tasks: u64,
    pub task_score_delta: Interval,
    pub cost_delta_usd: Interval,
    pub latency_delta_ms: Interval,
    pub candidate_safety_violations: u64,
    pub candidate_policy_violations: u64,
    pub train_eval_overlap: bool,
    pub replay_equivalence_passed: bool,
    pub sandbox_suite_passed: bool,
    pub invariant_suites: BTreeMap<String, bool>,
}

impl PromotionEvidence {
    /// Validate only the shape and bounds of caller assertions. This does not authenticate the
    /// producer, recompute digests, establish task pairing, or attest any suite result.
    pub fn validate_contract(&self) -> Result<(), ContractError> {
        self.baseline.validate()?;
        self.candidate.validate()?;
        self.base_model.validate()?;
        if !self.base_model.is_admissible() {
            return Err(ContractError::InvalidBaseModel(
                "promotion evidence cannot rest on an inadmissible base model identity",
            ));
        }
        validate_collection(
            "promotion_evidence.invariant_suites",
            self.invariant_suites.len(),
            MAX_INVARIANT_SUITES,
        )?;
        for suite in self.invariant_suites.keys() {
            validate_nonempty_string(
                "promotion_evidence.invariant_suite key",
                suite,
                MAX_SHORT_STRING_BYTES,
            )?;
        }
        if !self.task_score_delta.finite_and_ordered()
            || !self.cost_delta_usd.finite_and_ordered()
            || !self.latency_delta_ms.finite_and_ordered()
        {
            return Err(ContractError::MalformedMetricInterval);
        }
        Ok(())
    }
}

/// Non-authoritative assessment policy for one strategy slot. Hard invariants dominate all
/// optimization metrics, but satisfying this contract never authorizes a release.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionGate {
    pub min_paired_tasks: u64,
    pub min_task_score_lower_bound: f64,
    pub max_cost_delta_upper_bound_usd: f64,
    pub max_latency_delta_upper_bound_ms: f64,
    pub require_replay_equivalence: bool,
    pub require_sandbox_suite: bool,
    pub required_invariant_suites: BTreeSet<String>,
}

impl Default for PromotionGate {
    fn default() -> Self {
        Self {
            min_paired_tasks: 100,
            min_task_score_lower_bound: 0.0,
            // Conservative defaults permit no upper-confidence-bound cost or latency regression.
            max_cost_delta_upper_bound_usd: 0.0,
            max_latency_delta_upper_bound_ms: 0.0,
            require_replay_equivalence: true,
            require_sandbox_suite: true,
            required_invariant_suites: ["runtime".into(), "security".into(), "durability".into()]
                .into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionAssessment {
    /// The supplied assertions satisfy this assessor and may be submitted to a future release
    /// authority. No state transition has occurred.
    EligibleForReleaseReview {
        suggested_next: DeploymentStage,
    },
    Reject {
        reasons: Vec<String>,
    },
}

impl PromotionGate {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.min_paired_tasks == 0 {
            return Err(ContractError::InvalidPromotionGate(
                "min_paired_tasks must be greater than zero",
            ));
        }
        if !self.min_task_score_lower_bound.is_finite()
            || !self.max_cost_delta_upper_bound_usd.is_finite()
            || !self.max_latency_delta_upper_bound_ms.is_finite()
        {
            return Err(ContractError::InvalidPromotionGate(
                "thresholds must be finite",
            ));
        }
        if self.max_cost_delta_upper_bound_usd < 0.0 || self.max_latency_delta_upper_bound_ms < 0.0
        {
            return Err(ContractError::InvalidPromotionGate(
                "cost and latency ceilings must be non-negative",
            ));
        }
        validate_collection(
            "promotion_gate.required_invariant_suites",
            self.required_invariant_suites.len(),
            MAX_INVARIANT_SUITES,
        )?;
        for suite in &self.required_invariant_suites {
            validate_nonempty_string(
                "promotion_gate.required_invariant_suite",
                suite,
                MAX_SHORT_STRING_BYTES,
            )?;
        }
        Ok(())
    }

    /// Assess a proposed one-step transition using **untrusted caller assertions**. The returned
    /// value is review advice only: this crate has no registry handle or activation capability and
    /// cannot perform the suggested transition. A future authority must independently authenticate
    /// the current stage and evidence, enforce separation of duties, and commit registry state.
    pub fn assess(
        &self,
        asserted_from: DeploymentStage,
        evidence: &PromotionEvidence,
    ) -> PromotionAssessment {
        if let Err(error) = self.validate() {
            return PromotionAssessment::Reject {
                reasons: vec![format!("promotion assessor contract is invalid: {error}")],
            };
        }
        if let Err(error) = evidence.validate_contract() {
            return PromotionAssessment::Reject {
                reasons: vec![format!(
                    "untrusted promotion evidence fails contract validation: {error}"
                )],
            };
        }

        let target = match asserted_from {
            DeploymentStage::Candidate => Some(DeploymentStage::Shadow),
            DeploymentStage::Shadow => Some(DeploymentStage::Canary),
            DeploymentStage::Canary => Some(DeploymentStage::Active),
            _ => None,
        };
        let mut reasons = Vec::new();
        if evidence.baseline.slot != evidence.candidate.slot {
            reasons.push("baseline and candidate target different strategy slots".into());
        }
        if evidence.paired_tasks < self.min_paired_tasks {
            reasons.push(format!(
                "paired task count {} is below required {}",
                evidence.paired_tasks, self.min_paired_tasks
            ));
        }
        if evidence.task_score_delta.lower < self.min_task_score_lower_bound {
            reasons.push("task-score confidence bound misses the promotion floor".into());
        }
        if evidence.cost_delta_usd.upper > self.max_cost_delta_upper_bound_usd {
            reasons.push("cost confidence bound exceeds the promotion ceiling".into());
        }
        if evidence.latency_delta_ms.upper > self.max_latency_delta_upper_bound_ms {
            reasons.push("latency confidence bound exceeds the promotion ceiling".into());
        }
        if evidence.candidate_safety_violations > 0 {
            reasons.push("candidate has a safety violation; reward cannot compensate".into());
        }
        if evidence.candidate_policy_violations > 0 {
            reasons.push("candidate has a policy violation; reward cannot compensate".into());
        }
        if evidence.train_eval_overlap {
            reasons.push("training and evaluation sets overlap".into());
        }
        if self.require_replay_equivalence && !evidence.replay_equivalence_passed {
            reasons.push("replay-equivalence suite failed".into());
        }
        if self.require_sandbox_suite && !evidence.sandbox_suite_passed {
            reasons.push("sandbox suite failed".into());
        }
        for suite in &self.required_invariant_suites {
            if evidence.invariant_suites.get(suite) != Some(&true) {
                reasons.push(format!("required invariant suite `{suite}` did not pass"));
            }
        }
        if target.is_none() {
            reasons.push(format!(
                "asserted stage {asserted_from:?} has no forward assessment transition"
            ));
        }
        if reasons.is_empty() {
            PromotionAssessment::EligibleForReleaseReview {
                suggested_next: target.expect("checked"),
            }
        } else {
            PromotionAssessment::Reject { reasons }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn policy(slot: StrategySlot, id: &str) -> PolicyRef {
        PolicyRef {
            slot,
            policy_id: id.into(),
            version: "1.0.0".into(),
            digest: D.into(),
        }
    }

    fn evidence() -> PromotionEvidence {
        PromotionEvidence {
            base_model: BaseModelId {
                model_family: "anthropic/claude".into(),
                model_id: "claude-opus-5".into(),
                model_digest: "b".repeat(64),
            },
            baseline: policy(StrategySlot::router(), "baseline"),
            candidate: policy(StrategySlot::router(), "candidate"),
            paired_tasks: 200,
            task_score_delta: Interval {
                estimate: 0.04,
                lower: 0.01,
                upper: 0.07,
            },
            cost_delta_usd: Interval {
                estimate: -0.01,
                lower: -0.02,
                upper: 0.0,
            },
            latency_delta_ms: Interval {
                estimate: -5.0,
                lower: -8.0,
                upper: -2.0,
            },
            candidate_safety_violations: 0,
            candidate_policy_violations: 0,
            train_eval_overlap: false,
            replay_equivalence_passed: true,
            sandbox_suite_passed: true,
            invariant_suites: [
                ("runtime".into(), true),
                ("security".into(), true),
                ("durability".into(), true),
            ]
            .into(),
        }
    }

    fn bundle() -> PolicyBundle {
        PolicyBundle {
            bundle_id: "bundle-a".into(),
            digest: D.into(),
            policies: vec![policy(StrategySlot::router(), "router-a")],
            rollback_to: None,
        }
    }

    fn envelope(governance: DataGovernance) -> TrajectoryEnvelope {
        TrajectoryEnvelope {
            schema_version: EVOLUTION_SCHEMA_VERSION,
            run_id: RunId("run-a".into()),
            tenant_id: TenantId::default(),
            task_id: "task-a".into(),
            domain: "coding".into(),
            environment_digest: D.into(),
            bundle: bundle(),
            decisions: Vec::new(),
            terminal_outcome: "completed".into(),
            reward: RewardVector {
                task_score: 1.0,
                correctness: 1.0,
                safety_violations: 0,
                policy_violations: 0,
                cost_usd: 0.01,
                wall_time_ms: 10,
                human_acceptance: None,
                domain: BTreeMap::new(),
            },
            governance,
        }
    }

    fn training_policy() -> TrainingAdmissionPolicy {
        TrainingAdmissionPolicy::new(
            ["apache-2.0".to_owned()].into(),
            [
                ("training-v1".to_owned(), RetentionTrainingUse::Allowed),
                (
                    "enterprise-audit-30d".to_owned(),
                    RetentionTrainingUse::Prohibited,
                ),
            ]
            .into(),
        )
        .unwrap()
    }

    #[test]
    fn vertical_slots_are_open_but_namespaced_and_bounded() {
        assert_eq!(
            StrategySlot::new("coding/localizer").unwrap().as_str(),
            "coding/localizer"
        );
        assert!(StrategySlot::new("Coding Localizer").is_err());
        assert!(StrategySlot::new("/escape").is_err());
    }

    #[test]
    fn audit_envelope_can_be_valid_while_training_conversion_is_denied() {
        let audit_only = envelope(DataGovernance {
            class: DataClass::CustomerConfidential,
            consent: TrainingConsent::EvaluationOnly,
            content_license: None,
            contains_secret_material: false,
            retention_policy: "enterprise-audit-30d".into(),
        });
        assert!(audit_only.validate().is_ok());
        assert!(matches!(
            training_policy().admit(&audit_only),
            Err(TrainingEligibilityError::ConsentNotAllowed(
                TrainingConsent::EvaluationOnly
            ))
        ));
    }

    #[test]
    fn training_conversion_rejects_each_governance_boundary() {
        let allowed = DataGovernance {
            class: DataClass::Public,
            consent: TrainingConsent::Allowed,
            content_license: Some("apache-2.0".into()),
            contains_secret_material: false,
            retention_policy: "training-v1".into(),
        };
        let eligible = envelope(allowed.clone());
        let policy = training_policy();
        let proof = policy.admit(&eligible).unwrap();
        assert_eq!(proof.envelope().task_id, "task-a");
        assert!(matches!(
            TrainingEligibleTrajectory::try_from(&eligible),
            Err(TrainingEligibilityError::ExplicitAdmissionPolicyRequired)
        ));

        let contains_secret = envelope(DataGovernance {
            contains_secret_material: true,
            ..allowed.clone()
        });
        assert!(matches!(
            policy.validate_trajectory(&contains_secret),
            Err(TrainingEligibilityError::ContainsSecretMaterial)
        ));

        for class in [DataClass::Secret, DataClass::Unknown] {
            let prohibited = envelope(DataGovernance {
                class,
                ..allowed.clone()
            });
            assert!(matches!(
                policy.validate_trajectory(&prohibited),
                Err(TrainingEligibilityError::ProhibitedDataClass(actual)) if actual == class
            ));
        }

        let unlicensed = envelope(DataGovernance {
            content_license: Some("  ".into()),
            ..allowed
        });
        assert!(matches!(
            policy.validate_trajectory(&unlicensed),
            Err(TrainingEligibilityError::MissingContentLicense)
        ));
    }

    #[test]
    fn reward_improvement_can_never_pay_for_a_safety_regression() {
        let mut e = evidence();
        e.task_score_delta = Interval {
            estimate: 0.9,
            lower: 0.8,
            upper: 1.0,
        };
        e.candidate_safety_violations = 1;
        let d = PromotionGate::default().assess(DeploymentStage::Canary, &e);
        assert!(matches!(d, PromotionAssessment::Reject { .. }));
        let PromotionAssessment::Reject { reasons } = d else {
            unreachable!()
        };
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("reward cannot compensate"))
        );
    }

    #[test]
    fn train_eval_overlap_blocks_promotion() {
        let mut e = evidence();
        e.train_eval_overlap = true;
        assert!(matches!(
            PromotionGate::default().assess(DeploymentStage::Shadow, &e),
            PromotionAssessment::Reject { .. }
        ));
    }

    #[test]
    fn clean_assertions_only_recommend_one_stage_for_release_review() {
        let e = evidence();
        assert_eq!(
            PromotionGate::default().assess(DeploymentStage::Candidate, &e),
            PromotionAssessment::EligibleForReleaseReview {
                suggested_next: DeploymentStage::Shadow
            }
        );
        assert_eq!(
            PromotionGate::default().assess(DeploymentStage::Canary, &e),
            PromotionAssessment::EligibleForReleaseReview {
                suggested_next: DeploymentStage::Active
            }
        );
        assert!(matches!(
            PromotionGate::default().assess(DeploymentStage::Active, &e),
            PromotionAssessment::Reject { .. }
        ));
    }

    #[test]
    fn bundle_pins_exactly_one_policy_per_slot() {
        let p = policy(StrategySlot::router(), "router-a");
        let bundle = PolicyBundle {
            bundle_id: "bundle-a".into(),
            digest: D.into(),
            policies: vec![p.clone(), p],
            rollback_to: None,
        };
        assert!(matches!(
            bundle.validate(),
            Err(ContractError::DuplicateSlot(_))
        ));
    }

    #[test]
    fn learned_manifest_requires_training_provenance() {
        let manifest = PolicyManifest {
            schema_version: EVOLUTION_SCHEMA_VERSION,
            policy: policy(StrategySlot::planner(), "planner-grpo"),
            artifact_kind: ArtifactKind::ModelAdapter,
            artifact_locator: "registry://planner-grpo@1.0.0".into(),
            parent: None,
            method: EvolutionMethod::Grpo,
            protocol: ProtocolRange { min: 1, max: 1 },
            required_capabilities: BTreeSet::new(),
            training_dataset_digest: None,
            evaluation_suite_digest: D.into(),
            base_model: crate::BaseModelId::unspecified(),
        };
        assert!(matches!(
            manifest.validate(),
            Err(ContractError::MissingTrainingDataset(EvolutionMethod::Grpo))
        ));
    }

    #[test]
    fn malformed_policy_reference_cannot_pass_promotion() {
        let mut e = evidence();
        // Deserialization is an untrusted contract boundary and can bypass the smart constructor.
        e.candidate.slot = serde_json::from_str(r#""/invalid""#).unwrap();
        assert!(matches!(
            PromotionGate::default().assess(DeploymentStage::Canary, &e),
            PromotionAssessment::Reject { .. }
        ));
    }

    #[test]
    fn default_promotion_gate_is_portable_json() {
        assert!(PromotionGate::default().validate().is_ok());
        assert!(
            PromotionGate::default()
                .max_cost_delta_upper_bound_usd
                .is_finite()
        );
        assert!(
            PromotionGate::default()
                .max_latency_delta_upper_bound_ms
                .is_finite()
        );
        let encoded = serde_json::to_string(&PromotionGate::default()).unwrap();
        let decoded: PromotionGate = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, PromotionGate::default());
    }

    #[test]
    fn malformed_or_unbounded_assessor_contracts_fail_closed() {
        let gate = PromotionGate {
            min_paired_tasks: 0,
            ..PromotionGate::default()
        };
        assert!(matches!(
            gate.validate(),
            Err(ContractError::InvalidPromotionGate(_))
        ));
        assert!(matches!(
            gate.assess(DeploymentStage::Candidate, &evidence()),
            PromotionAssessment::Reject { .. }
        ));

        let too_many = PromotionGate {
            required_invariant_suites: (0..=MAX_INVARIANT_SUITES)
                .map(|index| format!("suite-{index}"))
                .collect(),
            ..PromotionGate::default()
        };
        assert!(matches!(
            too_many.validate(),
            Err(ContractError::CollectionTooLarge { .. })
        ));
    }

    #[test]
    fn attacker_controlled_strings_collections_and_json_are_bounded() {
        let mut oversized_id = envelope(DataGovernance {
            class: DataClass::Public,
            consent: TrainingConsent::Allowed,
            content_license: Some("apache-2.0".into()),
            contains_secret_material: false,
            retention_policy: "training-v1".into(),
        });
        oversized_id.task_id = "x".repeat(MAX_SHORT_STRING_BYTES + 1);
        assert!(matches!(
            oversized_id.validate(),
            Err(ContractError::StringTooLong { .. })
        ));

        let mut oversized_bundle = bundle();
        oversized_bundle.policies = (0..=MAX_POLICIES_PER_BUNDLE)
            .map(|index| policy(StrategySlot::new(format!("custom/{index}")).unwrap(), "p"))
            .collect();
        assert!(matches!(
            oversized_bundle.validate(),
            Err(ContractError::CollectionTooLarge { .. })
        ));

        let active_policy = bundle().policies.remove(0);
        let mut decision = StrategyDecision {
            decision_id: "decision-a".into(),
            ordinal: 0,
            policy: active_policy,
            observation_digest: D.into(),
            candidate_set_digest: D.into(),
            action: serde_json::Value::String("x".repeat(MAX_ACTION_JSON_BYTES + 1)),
            action_digest: D.into(),
            propensity: Some(1.0),
        };
        assert!(matches!(
            decision.validate(&bundle()),
            Err(ContractError::ActionJsonTooLarge { .. })
        ));

        let mut deeply_nested = serde_json::Value::Null;
        for _ in 0..MAX_ACTION_JSON_DEPTH {
            deeply_nested = serde_json::Value::Array(vec![deeply_nested]);
        }
        decision.action = deeply_nested;
        assert!(matches!(
            decision.validate(&bundle()),
            Err(ContractError::ActionJsonTooDeep { .. })
        ));

        decision.action =
            serde_json::Value::Array(vec![serde_json::Value::Null; MAX_ACTION_JSON_NODES]);
        assert!(matches!(
            decision.validate(&bundle()),
            Err(ContractError::ActionJsonTooManyNodes { .. })
        ));
    }
}
