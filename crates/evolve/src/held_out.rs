//! Fixture-backed projection of bounded held-out reports into signed promotion evidence.
//!
//! The frozen [`crate::HeldOutEvidenceBridge`] is deliberately a lookup seam: callers ask for
//! evidence by candidate digest and base model, and receive an already-signed attestation. This
//! module owns the work behind that lookup. It validates a report, derives pairing and
//! train/evaluation overlap from governed membership, projects eval-lane interval bounds into the
//! local [`crate::Interval`] shape, signs through [`crate::IndependentEvaluator`], and stores the
//! immutable result.
//!
//! There is intentionally no dependency on `iteron-eval`. Its statistical helpers are private and
//! return bounds without point estimates. The committed report format is the cross-crate boundary:
//! bounds come from the eval lane, while point estimates, pairing, hard-constraint counters, and
//! overlap are recomputed here from the paired rows and governed identities.

use crate::{
    BaseModelId, ContractError, EvaluationSuite, GovernedTrainingDataset, HeldOutEvaluation,
    HeldOutEvidenceBridge, IndependentEvaluator, Interval, MAX_EVALUATION_TASKS,
    MAX_INVARIANT_SUITES, MAX_SHORT_STRING_BYTES, PolicyRef, PromotionAuthorityError,
    PromotionEvidence, RewardVector, SignedHeldOutEvaluation, VerifiedCandidateInputs,
    VerifiedTrainingDataset, validate_collection, validate_digest, validate_nonempty_string,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const HELD_OUT_REPORT_SCHEMA_VERSION: u16 = 1;
pub const MAX_HELD_OUT_REPORT_TASKS: usize = MAX_EVALUATION_TASKS;
pub const MAX_HELD_OUT_EVIDENCE_RECORDS: usize = 256;
pub const MAX_HELD_OUT_REPORT_JSON_BYTES: usize = 4 * 1024 * 1024;

/// Confidence bounds emitted by the eval lane for one paired delta.
///
/// The point estimate is not accepted here: it is recomputed from the paired rows so a fixture
/// cannot make the estimate disagree with the observations it carries.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutMetricBounds {
    pub lower: f64,
    pub upper: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutReportIntervals {
    pub task_score_delta: HeldOutMetricBounds,
    pub cost_delta_usd: HeldOutMetricBounds,
    pub latency_delta_ms: HeldOutMetricBounds,
}

/// One exactly paired baseline/candidate held-out task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutTaskPair {
    pub task_id: String,
    pub fixture_digest: String,
    pub baseline: RewardVector,
    pub candidate: RewardVector,
}

/// Bounded report format committed as the stub between the eval and evolution lanes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutEvalReport {
    pub schema_version: u16,
    pub baseline: PolicyRef,
    pub candidate: PolicyRef,
    pub pairs: Vec<HeldOutTaskPair>,
    pub intervals: HeldOutReportIntervals,
    pub replay_equivalence_passed: bool,
    pub sandbox_suite_passed: bool,
    pub invariant_suites: BTreeMap<String, bool>,
    /// Diagnostic assertion from a foreign report, retained only to prove it is never trusted.
    ///
    /// The emitted value is always recomputed from governed membership below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_train_eval_overlap: Option<bool>,
}

impl HeldOutEvalReport {
    pub fn from_json(bytes: &[u8]) -> Result<Self, HeldOutBridgeError> {
        if bytes.len() > MAX_HELD_OUT_REPORT_JSON_BYTES {
            return Err(HeldOutBridgeError::ReportTooLarge {
                max: MAX_HELD_OUT_REPORT_JSON_BYTES,
                actual: bytes.len(),
            });
        }
        let report: Self =
            serde_json::from_slice(bytes).map_err(HeldOutBridgeError::InvalidReportJson)?;
        report.validate()?;
        Ok(report)
    }

    fn validate(&self) -> Result<(), HeldOutBridgeError> {
        if self.schema_version != HELD_OUT_REPORT_SCHEMA_VERSION {
            return Err(HeldOutBridgeError::UnsupportedReportSchema(
                self.schema_version,
            ));
        }
        self.baseline.validate()?;
        self.candidate.validate()?;
        if self.baseline.slot != self.candidate.slot {
            return Err(HeldOutBridgeError::PolicySlotMismatch);
        }
        if self.pairs.is_empty() || self.pairs.len() > MAX_HELD_OUT_REPORT_TASKS {
            return Err(HeldOutBridgeError::InvalidPairCount {
                max: MAX_HELD_OUT_REPORT_TASKS,
                actual: self.pairs.len(),
            });
        }
        let mut task_ids = BTreeSet::new();
        for pair in &self.pairs {
            validate_nonempty_string(
                "held_out_report.task_id",
                &pair.task_id,
                MAX_SHORT_STRING_BYTES,
            )?;
            validate_digest(&pair.fixture_digest)?;
            pair.baseline.validate()?;
            pair.candidate.validate()?;
            if pair.baseline.cost_usd < 0.0 || pair.candidate.cost_usd < 0.0 {
                return Err(HeldOutBridgeError::NegativeCost);
            }
            if !task_ids.insert(pair.task_id.clone()) {
                return Err(HeldOutBridgeError::DuplicateTask(pair.task_id.clone()));
            }
        }
        validate_collection(
            "held_out_report.invariant_suites",
            self.invariant_suites.len(),
            MAX_INVARIANT_SUITES,
        )?;
        for suite in self.invariant_suites.keys() {
            validate_nonempty_string(
                "held_out_report.invariant_suite",
                suite,
                MAX_SHORT_STRING_BYTES,
            )?;
        }
        for bounds in [
            self.intervals.task_score_delta,
            self.intervals.cost_delta_usd,
            self.intervals.latency_delta_ms,
        ] {
            if !bounds.lower.is_finite() || !bounds.upper.is_finite() || bounds.lower > bounds.upper
            {
                return Err(HeldOutBridgeError::MalformedIntervalBounds);
            }
        }
        Ok(())
    }
}

/// Content-addressed training membership used solely for authentic overlap detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldOutTrainingCorpus {
    digest: String,
    task_ids: BTreeSet<String>,
}

impl HeldOutTrainingCorpus {
    pub fn from_verified(dataset: &VerifiedTrainingDataset<'_>) -> Self {
        Self {
            digest: dataset.digest().to_owned(),
            task_ids: dataset
                .members()
                .iter()
                .map(|member| member.envelope().task_id.clone())
                .collect(),
        }
    }

    pub fn from_governed(dataset: &GovernedTrainingDataset<'_>) -> Self {
        Self {
            digest: dataset.digest().to_owned(),
            task_ids: dataset
                .trajectories()
                .iter()
                .map(|trajectory| trajectory.task_id.clone())
                .collect(),
        }
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn task_ids(&self) -> &BTreeSet<String> {
        &self.task_ids
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldOutEvidenceRegistration {
    Stored,
    AlreadyPresent,
}

/// Bounded immutable-attestation lookup implementing the frozen seam.
#[derive(Debug, Default, Clone)]
pub struct HeldOutEvidenceStore {
    entries: BTreeMap<(String, BaseModelId), SignedHeldOutEvaluation>,
}

impl HeldOutEvidenceStore {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &mut self,
        mut report: HeldOutEvalReport,
        candidate: &PolicyRef,
        verified: &VerifiedCandidateInputs,
        training: Option<&HeldOutTrainingCorpus>,
        suite: &EvaluationSuite,
        evaluator: &IndependentEvaluator,
        promotion_party_ids: &BTreeSet<String>,
    ) -> Result<HeldOutEvidenceRegistration, HeldOutBridgeError> {
        report.validate()?;
        report
            .pairs
            .sort_by(|left, right| left.task_id.as_bytes().cmp(right.task_id.as_bytes()));
        if &report.candidate != candidate
            || report.candidate.digest != verified.artifact_digest
            || verified.evaluation_suite_digest != suite.digest()
        {
            return Err(HeldOutBridgeError::CandidateIdentityMismatch);
        }
        if !verified.base_model.is_admissible() {
            return Err(HeldOutBridgeError::InadmissibleBaseModel);
        }
        if promotion_party_ids.contains(evaluator.evaluator_id()) {
            return Err(HeldOutBridgeError::EvaluatorIsPromotionParty(
                evaluator.evaluator_id().to_owned(),
            ));
        }

        match (&verified.training_dataset_digest, training) {
            (Some(expected), Some(training)) if expected == training.digest() => {}
            (None, None) => {}
            _ => return Err(HeldOutBridgeError::TrainingDatasetMismatch),
        }

        let expected_tasks: BTreeMap<_, _> = suite
            .tasks()
            .iter()
            .map(|task| (task.task_id.as_str(), task.fixture_digest.as_str()))
            .collect();
        let reported_tasks: BTreeMap<_, _> = report
            .pairs
            .iter()
            .map(|pair| (pair.task_id.as_str(), pair.fixture_digest.as_str()))
            .collect();
        if expected_tasks != reported_tasks {
            return Err(HeldOutBridgeError::EvaluationSuiteMismatch);
        }

        let paired_tasks = report.pairs.len() as u64;
        let denominator = paired_tasks as f64;
        let mean_delta = |value: fn(&RewardVector) -> f64| {
            report
                .pairs
                .iter()
                .map(|pair| value(&pair.candidate) - value(&pair.baseline))
                .sum::<f64>()
                / denominator
        };
        let task_score_estimate = mean_delta(|reward| reward.task_score);
        let cost_estimate = mean_delta(|reward| reward.cost_usd);
        let latency_estimate = mean_delta(|reward| reward.wall_time_ms as f64);
        let train_eval_overlap = training.is_some_and(|training| {
            report
                .pairs
                .iter()
                .any(|pair| training.task_ids.contains(&pair.task_id))
        });
        let candidate_safety_violations = sum_hard_constraint(
            &report.pairs,
            |reward| reward.safety_violations,
            "candidate safety violation count overflowed",
        )?;
        let candidate_policy_violations = sum_hard_constraint(
            &report.pairs,
            |reward| reward.policy_violations,
            "candidate policy violation count overflowed",
        )?;

        let evidence = PromotionEvidence {
            baseline: report.baseline,
            candidate: report.candidate,
            base_model: verified.base_model.clone(),
            paired_tasks,
            task_score_delta: interval(task_score_estimate, report.intervals.task_score_delta)?,
            cost_delta_usd: interval(cost_estimate, report.intervals.cost_delta_usd)?,
            latency_delta_ms: interval(latency_estimate, report.intervals.latency_delta_ms)?,
            candidate_safety_violations,
            candidate_policy_violations,
            train_eval_overlap,
            replay_equivalence_passed: report.replay_equivalence_passed,
            sandbox_suite_passed: report.sandbox_suite_passed,
            invariant_suites: report.invariant_suites,
        };
        evidence.validate_contract()?;
        let held_out = HeldOutEvaluation::new(candidate.clone(), verified, evidence)?;
        let signed = evaluator.sign_held_out(held_out)?;
        let key = (candidate.digest.clone(), verified.base_model.clone());

        if let Some(existing) = self.entries.get(&key) {
            return if existing == &signed {
                Ok(HeldOutEvidenceRegistration::AlreadyPresent)
            } else {
                Err(HeldOutBridgeError::ConflictingEvidence)
            };
        }
        if self.entries.len() >= MAX_HELD_OUT_EVIDENCE_RECORDS {
            return Err(HeldOutBridgeError::EvidenceLimit {
                max: MAX_HELD_OUT_EVIDENCE_RECORDS,
            });
        }
        self.entries.insert(key, signed);
        Ok(HeldOutEvidenceRegistration::Stored)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl HeldOutEvidenceBridge for HeldOutEvidenceStore {
    fn evidence_for(
        &self,
        policy_digest: &str,
        base_model: &BaseModelId,
    ) -> Result<Option<SignedHeldOutEvaluation>, ContractError> {
        validate_digest(policy_digest)?;
        base_model.validate()?;
        if !base_model.is_admissible() {
            return Err(ContractError::InvalidBaseModel(
                "held-out evidence lookup requires an admissible base model",
            ));
        }
        Ok(self
            .entries
            .get(&(policy_digest.to_owned(), base_model.clone()))
            .cloned())
    }
}

fn interval(estimate: f64, bounds: HeldOutMetricBounds) -> Result<Interval, HeldOutBridgeError> {
    if !estimate.is_finite() || estimate < bounds.lower || estimate > bounds.upper {
        return Err(HeldOutBridgeError::EstimateOutsideInterval);
    }
    Ok(Interval {
        estimate,
        lower: bounds.lower,
        upper: bounds.upper,
    })
}

fn sum_hard_constraint(
    pairs: &[HeldOutTaskPair],
    value: fn(&RewardVector) -> u32,
    message: &'static str,
) -> Result<u64, HeldOutBridgeError> {
    pairs.iter().try_fold(0_u64, |total, pair| {
        total
            .checked_add(u64::from(value(&pair.candidate)))
            .ok_or(HeldOutBridgeError::CountOverflow(message))
    })
}

#[derive(Debug, thiserror::Error)]
pub enum HeldOutBridgeError {
    #[error("held-out report JSON is invalid: {0}")]
    InvalidReportJson(#[source] serde_json::Error),
    #[error("held-out report JSON is {actual} bytes; limit is {max}")]
    ReportTooLarge { max: usize, actual: usize },
    #[error("held-out report schema {0} is not supported")]
    UnsupportedReportSchema(u16),
    #[error("held-out report contract is invalid: {0}")]
    InvalidContract(#[from] ContractError),
    #[error("held-out report has {actual} pairs; expected 1..={max}")]
    InvalidPairCount { max: usize, actual: usize },
    #[error("held-out report contains duplicate task `{0}`")]
    DuplicateTask(String),
    #[error("held-out baseline and candidate target different slots")]
    PolicySlotMismatch,
    #[error("held-out report carries a negative observed cost")]
    NegativeCost,
    #[error("held-out report interval bounds are non-finite or inverted")]
    MalformedIntervalBounds,
    #[error("held-out point estimate is non-finite or outside eval-lane confidence bounds")]
    EstimateOutsideInterval,
    #[error("held-out report does not match the verified candidate identity")]
    CandidateIdentityMismatch,
    #[error("held-out report task membership does not exactly match the governed evaluation suite")]
    EvaluationSuiteMismatch,
    #[error("held-out report training membership does not match the verified dataset digest")]
    TrainingDatasetMismatch,
    #[error("held-out evidence cannot rest on an inadmissible base model")]
    InadmissibleBaseModel,
    #[error("independent evaluator `{0}` is also configured as a promotion party")]
    EvaluatorIsPromotionParty(String),
    #[error("held-out hard-constraint count is invalid: {0}")]
    CountOverflow(&'static str),
    #[error("held-out evidence conflicts with an immutable record at the same identity")]
    ConflictingEvidence,
    #[error("held-out evidence store reached its fixed {max}-record limit")]
    EvidenceLimit { max: usize },
    #[error("held-out evaluation could not be signed or bound: {0}")]
    Promotion(#[from] PromotionAuthorityError),
}

#[cfg(test)]
#[path = "held_out_tests.rs"]
mod tests;
