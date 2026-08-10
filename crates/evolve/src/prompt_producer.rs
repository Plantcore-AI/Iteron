//! Deterministic offline prompt preference producer.
//!
//! This is intentionally a different method and artifact kind from
//! [`crate::OfflineRuleSearchProducer`]: it emits an inert `Prompt` artifact under
//! `PreferenceOptimization`. Both return the same [`crate::ProducedPolicyCandidate`] carrier and
//! pass through the same manifest validation and intersection-only admission policy.

use crate::dataset::sha256_hex;
use crate::{
    ArtifactKind, BaseModelId, CapabilityAdmissionError, ContractError, EvolutionMethod,
    GovernedTrainingDataset, MAX_REQUIRED_CAPABILITIES, MAX_SHORT_STRING_BYTES,
    ManifestAdmissionPolicy, PolicyManifest, PolicyRef, ProducedPolicyCandidate, ProtocolRange,
    validate_collection, validate_digest, validate_nonempty_string,
};
use iteron_protocol::Capability;
use serde::Serialize;
use std::collections::BTreeSet;

pub const MAX_PROMPT_PREFERENCE_CANDIDATES: usize = 128;
pub const MAX_INERT_PROMPT_ARTIFACT_BYTES: usize = 16 * 1_024;
const MAX_PROMPT_TEMPLATE_BYTES: usize = 4 * 1_024;
const MAX_PROMPT_SEARCH_SPACE_BYTES: usize = 1_024 * 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PromptPreferenceCandidate {
    candidate_id: String,
    target_domain: String,
    preferred_terminal_outcome: String,
    prompt_template: String,
}

impl PromptPreferenceCandidate {
    pub fn new(
        candidate_id: impl Into<String>,
        target_domain: impl Into<String>,
        preferred_terminal_outcome: impl Into<String>,
        prompt_template: impl Into<String>,
    ) -> Result<Self, PromptPreferenceError> {
        let candidate = Self {
            candidate_id: candidate_id.into(),
            target_domain: target_domain.into(),
            preferred_terminal_outcome: preferred_terminal_outcome.into(),
            prompt_template: prompt_template.into(),
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    pub fn prompt_template(&self) -> &str {
        &self.prompt_template
    }

    fn validate(&self) -> Result<(), PromptPreferenceError> {
        validate_nonempty_string(
            "prompt_preference.candidate_id",
            &self.candidate_id,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string(
            "prompt_preference.target_domain",
            &self.target_domain,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string(
            "prompt_preference.preferred_terminal_outcome",
            &self.preferred_terminal_outcome,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string(
            "prompt_preference.prompt_template",
            &self.prompt_template,
            MAX_PROMPT_TEMPLATE_BYTES,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptPreferenceSpec {
    policy_id: String,
    base_model: BaseModelId,
    version: String,
    parent: Option<PolicyRef>,
    protocol: ProtocolRange,
    required_capabilities: BTreeSet<Capability>,
    evaluation_suite_digest: String,
    candidates: Vec<PromptPreferenceCandidate>,
}

impl PromptPreferenceSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        base_model: BaseModelId,
        version: impl Into<String>,
        parent: Option<PolicyRef>,
        protocol: ProtocolRange,
        required_capabilities: BTreeSet<Capability>,
        evaluation_suite_digest: impl Into<String>,
        mut candidates: Vec<PromptPreferenceCandidate>,
    ) -> Result<Self, PromptPreferenceError> {
        let policy_id = policy_id.into();
        let version = version.into();
        let evaluation_suite_digest = evaluation_suite_digest.into();
        validate_nonempty_string(
            "prompt_preference.policy_id",
            &policy_id,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string(
            "prompt_preference.version",
            &version,
            MAX_SHORT_STRING_BYTES,
        )?;
        base_model.validate()?;
        if !base_model.is_admissible() {
            return Err(PromptPreferenceError::InadmissibleBaseModel);
        }
        if protocol.min > protocol.max {
            return Err(ContractError::InvertedProtocolRange.into());
        }
        validate_collection(
            "prompt_preference.required_capabilities",
            required_capabilities.len(),
            MAX_REQUIRED_CAPABILITIES,
        )?;
        validate_digest(&evaluation_suite_digest)?;
        if let Some(parent) = &parent {
            parent.validate()?;
        }
        if candidates.is_empty() {
            return Err(PromptPreferenceError::EmptyCandidateSet);
        }
        if candidates.len() > MAX_PROMPT_PREFERENCE_CANDIDATES {
            return Err(PromptPreferenceError::TooManyCandidates {
                max: MAX_PROMPT_PREFERENCE_CANDIDATES,
                actual: candidates.len(),
            });
        }
        for candidate in &candidates {
            candidate.validate()?;
        }
        candidates.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
        if candidates
            .windows(2)
            .any(|pair| pair[0].candidate_id == pair[1].candidate_id)
        {
            return Err(PromptPreferenceError::DuplicateCandidateId);
        }
        Ok(Self {
            policy_id,
            base_model,
            version,
            parent,
            protocol,
            required_capabilities,
            evaluation_suite_digest,
            candidates,
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PromptPreferenceProducer;

impl PromptPreferenceProducer {
    pub const fn new() -> Self {
        Self
    }

    pub fn produce(
        &self,
        dataset: &GovernedTrainingDataset<'_>,
        admission_policy: &ManifestAdmissionPolicy,
        spec: &PromptPreferenceSpec,
    ) -> Result<ProducedPolicyCandidate, PromptPreferenceError> {
        if spec.evaluation_suite_digest == dataset.digest() {
            return Err(PromptPreferenceError::EvaluationSuiteMatchesTrainingDataset);
        }
        let search_space =
            serde_json::to_vec(&spec.candidates).map_err(PromptPreferenceError::Encoding)?;
        if search_space.len() > MAX_PROMPT_SEARCH_SPACE_BYTES {
            return Err(PromptPreferenceError::SearchSpaceTooLarge {
                max: MAX_PROMPT_SEARCH_SPACE_BYTES,
            });
        }
        let selected = select_candidate(dataset, &spec.candidates);
        let preference_score = candidate_score(dataset, selected);
        let artifact = InertPromptArtifact {
            schema_version: 1,
            producer: "offline_prompt_preference_v1",
            selected_candidate_id: &selected.candidate_id,
            target_domain: &selected.target_domain,
            preferred_terminal_outcome: &selected.preferred_terminal_outcome,
            prompt_template: &selected.prompt_template,
            preference_score,
            search_space_digest: sha256_hex(&search_space),
            training_dataset_digest: dataset.digest(),
        };
        let artifact_bytes =
            serde_json::to_vec(&artifact).map_err(PromptPreferenceError::Encoding)?;
        if artifact_bytes.len() > MAX_INERT_PROMPT_ARTIFACT_BYTES {
            return Err(PromptPreferenceError::ArtifactTooLarge {
                max: MAX_INERT_PROMPT_ARTIFACT_BYTES,
                actual: artifact_bytes.len(),
            });
        }
        let artifact_digest = sha256_hex(&artifact_bytes);
        let manifest = PolicyManifest {
            schema_version: crate::EVOLUTION_SCHEMA_VERSION,
            policy: PolicyRef {
                slot: admission_policy.slot().clone(),
                policy_id: spec.policy_id.clone(),
                version: spec.version.clone(),
                digest: artifact_digest.clone(),
            },
            artifact_kind: ArtifactKind::Prompt,
            artifact_locator: format!("inert:sha256:{artifact_digest}"),
            parent: spec.parent.clone(),
            method: EvolutionMethod::PreferenceOptimization,
            protocol: spec.protocol.clone(),
            required_capabilities: spec.required_capabilities.clone(),
            training_dataset_digest: Some(dataset.digest().to_owned()),
            evaluation_suite_digest: spec.evaluation_suite_digest.clone(),
            base_model: spec.base_model.clone(),
        };
        manifest.validate()?;
        let capability_admission = admission_policy.assess(&manifest)?;
        Ok(ProducedPolicyCandidate::from_parts(
            artifact_bytes,
            manifest,
            capability_admission,
            selected.candidate_id.clone(),
        ))
    }
}

fn select_candidate<'a>(
    dataset: &GovernedTrainingDataset<'_>,
    candidates: &'a [PromptPreferenceCandidate],
) -> &'a PromptPreferenceCandidate {
    let mut best = &candidates[0];
    let mut best_score = candidate_score(dataset, best);
    for candidate in &candidates[1..] {
        let score = candidate_score(dataset, candidate);
        if score > best_score || (score == best_score && candidate.candidate_id < best.candidate_id)
        {
            best = candidate;
            best_score = score;
        }
    }
    best
}

fn candidate_score(
    dataset: &GovernedTrainingDataset<'_>,
    candidate: &PromptPreferenceCandidate,
) -> f64 {
    dataset
        .trajectories()
        .iter()
        .filter(|trajectory| {
            trajectory.domain == candidate.target_domain
                && trajectory.terminal_outcome == candidate.preferred_terminal_outcome
                && trajectory.reward.safety_violations == 0
                && trajectory.reward.policy_violations == 0
        })
        .filter_map(|trajectory| trajectory.reward.human_acceptance)
        .filter(|score| score.is_finite())
        .sum()
}

#[derive(Serialize)]
struct InertPromptArtifact<'a> {
    schema_version: u16,
    producer: &'static str,
    selected_candidate_id: &'a str,
    target_domain: &'a str,
    preferred_terminal_outcome: &'a str,
    prompt_template: &'a str,
    preference_score: f64,
    search_space_digest: String,
    training_dataset_digest: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum PromptPreferenceError {
    #[error("prompt preference input contract is invalid: {0}")]
    InvalidInput(#[from] ContractError),
    #[error("prompt preference producer requires at least one candidate")]
    EmptyCandidateSet,
    #[error("prompt preference candidate count is {actual}; limit is {max}")]
    TooManyCandidates { max: usize, actual: usize },
    #[error("prompt preference candidates contain a duplicate id")]
    DuplicateCandidateId,
    #[error("prompt preference search space exceeds {max} bytes")]
    SearchSpaceTooLarge { max: usize },
    #[error("prompt preference artifact is {actual} bytes; limit is {max}")]
    ArtifactTooLarge { max: usize, actual: usize },
    #[error("evaluation suite digest must differ from the training dataset digest")]
    EvaluationSuiteMatchesTrainingDataset,
    #[error("prompt preference producer requires an admissible base model")]
    InadmissibleBaseModel,
    #[error("prompt preference candidate capability admission failed: {0}")]
    CapabilityAdmission(#[from] CapabilityAdmissionError),
    #[error("prompt preference artifact encoding failed: {0}")]
    Encoding(#[source] serde_json::Error),
}

#[cfg(test)]
#[path = "prompt_producer_tests.rs"]
mod tests;
