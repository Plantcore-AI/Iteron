//! Deterministic, bounded offline rule search.
//!
//! The producer consumes only a [`crate::GovernedTrainingDataset`], selects one inert rule from a
//! bounded search space, and returns bytes plus a manifest. It has no filesystem, loader, registry,
//! runtime, or activation handle.

use crate::dataset::sha256_hex;
use crate::{
    ArtifactKind, CapabilityAdmission, CapabilityAdmissionError, ContractError, EvolutionMethod,
    GovernedTrainingDataset, MAX_REQUIRED_CAPABILITIES, MAX_SHORT_STRING_BYTES,
    ManifestAdmissionPolicy, PolicyManifest, PolicyRef, ProtocolRange, validate_collection,
    validate_digest, validate_nonempty_string,
};
use core_protocol::Capability;
use serde::Serialize;
use std::collections::BTreeSet;

pub const MAX_OFFLINE_RULE_CANDIDATES: usize = 128;
pub const MAX_INERT_RULE_ARTIFACT_BYTES: usize = 16 * 1_024;
const MAX_OFFLINE_RULE_SEARCH_SPACE_BYTES: usize = 1_024 * 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfflineRuleCandidate {
    candidate_id: String,
    match_domain: String,
    preferred_terminal_outcome: String,
}

impl OfflineRuleCandidate {
    pub fn new(
        candidate_id: impl Into<String>,
        match_domain: impl Into<String>,
        preferred_terminal_outcome: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let candidate = Self {
            candidate_id: candidate_id.into(),
            match_domain: match_domain.into(),
            preferred_terminal_outcome: preferred_terminal_outcome.into(),
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    pub fn match_domain(&self) -> &str {
        &self.match_domain
    }

    pub fn preferred_terminal_outcome(&self) -> &str {
        &self.preferred_terminal_outcome
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_nonempty_string(
            "offline_rule.candidate_id",
            &self.candidate_id,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string(
            "offline_rule.match_domain",
            &self.match_domain,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string(
            "offline_rule.preferred_terminal_outcome",
            &self.preferred_terminal_outcome,
            MAX_SHORT_STRING_BYTES,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineRuleSearchSpec {
    policy_id: String,
    version: String,
    parent: Option<PolicyRef>,
    protocol: ProtocolRange,
    required_capabilities: BTreeSet<Capability>,
    evaluation_suite_digest: String,
    candidates: Vec<OfflineRuleCandidate>,
}

impl OfflineRuleSearchSpec {
    /// Define a bounded search. `evaluation_suite_digest` must come from a separately governed,
    /// held-out suite. The producer can validate its encoding and reject equality with the
    /// training dataset digest, but cannot itself prove semantic non-overlap.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        version: impl Into<String>,
        parent: Option<PolicyRef>,
        protocol: ProtocolRange,
        required_capabilities: BTreeSet<Capability>,
        evaluation_suite_digest: impl Into<String>,
        mut candidates: Vec<OfflineRuleCandidate>,
    ) -> Result<Self, OfflineProducerError> {
        let policy_id = policy_id.into();
        let version = version.into();
        let evaluation_suite_digest = evaluation_suite_digest.into();
        validate_nonempty_string(
            "offline_search.policy_id",
            &policy_id,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string("offline_search.version", &version, MAX_SHORT_STRING_BYTES)?;
        if protocol.min > protocol.max {
            return Err(ContractError::InvertedProtocolRange.into());
        }
        validate_collection(
            "offline_search.required_capabilities",
            required_capabilities.len(),
            MAX_REQUIRED_CAPABILITIES,
        )?;
        validate_digest(&evaluation_suite_digest)?;
        if let Some(parent) = &parent {
            parent.validate()?;
        }
        if candidates.is_empty() {
            return Err(OfflineProducerError::EmptyRuleSearchSpace);
        }
        if candidates.len() > MAX_OFFLINE_RULE_CANDIDATES {
            return Err(OfflineProducerError::TooManyRuleCandidates {
                limit: MAX_OFFLINE_RULE_CANDIDATES,
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
            return Err(OfflineProducerError::DuplicateRuleCandidateId);
        }

        Ok(Self {
            policy_id,
            version,
            parent,
            protocol,
            required_capabilities,
            evaluation_suite_digest,
            candidates,
        })
    }

    pub fn evaluation_suite_digest(&self) -> &str {
        &self.evaluation_suite_digest
    }

    pub fn required_capabilities(&self) -> &BTreeSet<Capability> {
        &self.required_capabilities
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OfflineProducerError {
    #[error("offline producer input contract is invalid: {0}")]
    InvalidInput(#[from] ContractError),
    #[error("offline rule search requires at least one candidate")]
    EmptyRuleSearchSpace,
    #[error("offline rule search contains {actual} candidates; limit is {limit}")]
    TooManyRuleCandidates { limit: usize, actual: usize },
    #[error("offline rule search contains a duplicate candidate id")]
    DuplicateRuleCandidateId,
    #[error("offline rule search space exceeds {limit} canonical JSON bytes")]
    SearchSpaceTooLarge { limit: usize },
    #[error("evaluation suite digest must be independent from the training dataset digest")]
    EvaluationSuiteMatchesTrainingDataset,
    #[error("inert rule artifact exceeds {limit} bytes")]
    ArtifactTooLarge { limit: usize },
    #[error("offline producer could not encode deterministic JSON: {0}")]
    Encoding(#[source] serde_json::Error),
    #[error("candidate capability admission failed: {0}")]
    CapabilityAdmission(#[from] CapabilityAdmissionError),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OfflineRuleSearchProducer;

impl OfflineRuleSearchProducer {
    pub const fn new() -> Self {
        Self
    }

    pub fn produce(
        &self,
        dataset: &GovernedTrainingDataset<'_>,
        admission_policy: &ManifestAdmissionPolicy,
        spec: &OfflineRuleSearchSpec,
    ) -> Result<ProducedPolicyCandidate, OfflineProducerError> {
        if spec.evaluation_suite_digest == dataset.digest() {
            return Err(OfflineProducerError::EvaluationSuiteMatchesTrainingDataset);
        }

        let selected = select_rule(dataset, &spec.candidates);
        let matched_trajectories = rule_score(dataset, selected);
        let search_space_bytes =
            serde_json::to_vec(&spec.candidates).map_err(OfflineProducerError::Encoding)?;
        if search_space_bytes.len() > MAX_OFFLINE_RULE_SEARCH_SPACE_BYTES {
            return Err(OfflineProducerError::SearchSpaceTooLarge {
                limit: MAX_OFFLINE_RULE_SEARCH_SPACE_BYTES,
            });
        }
        let search_space_digest = sha256_hex(&search_space_bytes);

        let artifact = InertRuleArtifact {
            schema_version: 1,
            producer: "offline_rule_search_v1",
            selected_candidate_id: &selected.candidate_id,
            match_domain: &selected.match_domain,
            preferred_terminal_outcome: &selected.preferred_terminal_outcome,
            safe_matching_trajectories: matched_trajectories,
            search_space_digest: &search_space_digest,
            training_dataset_digest: dataset.digest(),
        };
        let artifact_bytes =
            serde_json::to_vec(&artifact).map_err(OfflineProducerError::Encoding)?;
        if artifact_bytes.len() > MAX_INERT_RULE_ARTIFACT_BYTES {
            return Err(OfflineProducerError::ArtifactTooLarge {
                limit: MAX_INERT_RULE_ARTIFACT_BYTES,
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
            artifact_kind: ArtifactKind::Rules,
            artifact_locator: format!("inert:sha256:{artifact_digest}"),
            parent: spec.parent.clone(),
            method: EvolutionMethod::Search,
            protocol: spec.protocol.clone(),
            required_capabilities: spec.required_capabilities.clone(),
            training_dataset_digest: Some(dataset.digest().to_owned()),
            evaluation_suite_digest: spec.evaluation_suite_digest.clone(),
        };
        manifest.validate()?;
        let capability_admission = admission_policy.assess(&manifest)?;

        Ok(ProducedPolicyCandidate {
            artifact_bytes,
            manifest,
            capability_admission,
            selected_candidate_id: selected.candidate_id.clone(),
        })
    }
}

fn select_rule<'a>(
    dataset: &GovernedTrainingDataset<'_>,
    candidates: &'a [OfflineRuleCandidate],
) -> &'a OfflineRuleCandidate {
    let mut best = &candidates[0];
    let mut best_score = rule_score(dataset, best);
    for candidate in &candidates[1..] {
        let score = rule_score(dataset, candidate);
        if score > best_score || (score == best_score && candidate.candidate_id < best.candidate_id)
        {
            best = candidate;
            best_score = score;
        }
    }
    best
}

fn rule_score(dataset: &GovernedTrainingDataset<'_>, candidate: &OfflineRuleCandidate) -> usize {
    dataset
        .trajectories()
        .iter()
        .filter(|trajectory| {
            trajectory.domain == candidate.match_domain
                && trajectory.terminal_outcome == candidate.preferred_terminal_outcome
                && trajectory.reward.safety_violations == 0
                && trajectory.reward.policy_violations == 0
        })
        .count()
}

#[derive(Serialize)]
struct InertRuleArtifact<'a> {
    schema_version: u16,
    producer: &'static str,
    selected_candidate_id: &'a str,
    match_domain: &'a str,
    preferred_terminal_outcome: &'a str,
    safe_matching_trajectories: usize,
    search_space_digest: &'a str,
    training_dataset_digest: &'a str,
}

/// Pure data returned by offline production. No method writes, loads, activates, or registers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducedPolicyCandidate {
    artifact_bytes: Vec<u8>,
    manifest: PolicyManifest,
    capability_admission: CapabilityAdmission,
    selected_candidate_id: String,
}

impl ProducedPolicyCandidate {
    pub fn artifact_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }

    pub fn manifest(&self) -> &PolicyManifest {
        &self.manifest
    }

    pub fn capability_admission(&self) -> &CapabilityAdmission {
        &self.capability_admission
    }

    pub fn selected_candidate_id(&self) -> &str {
        &self.selected_candidate_id
    }

    pub fn candidate_digest(&self) -> &str {
        &self.manifest.policy.digest
    }
}

#[cfg(test)]
#[path = "producer_tests.rs"]
mod tests;
