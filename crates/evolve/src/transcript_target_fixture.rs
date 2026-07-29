//! Bounded committed observation templates for the transcript's target-model held-out runs.
//!
//! The fixture deliberately does not carry a base-model identity. The frozen held-out boundary
//! binds that identity from [`crate::VerifiedCandidateInputs`] after the rebound manifest has been
//! independently verified, so a foreign observation cannot choose which model it attests.

use crate::{
    EvaluationSuite, HeldOutEvalReport, HeldOutMetricBounds, HeldOutReportIntervals,
    HeldOutTaskPair, MAX_INVARIANT_SUITES, PolicyRef, RewardVector, TranscriptRunError,
};
use serde::Deserialize;
use std::collections::BTreeMap;

const SAFE_FIXTURE: &[u8] =
    include_bytes!("../tests/fixtures/held-out-target-observation-safe-v1.json");
const UNSAFE_FIXTURE: &[u8] =
    include_bytes!("../tests/fixtures/held-out-target-observation-unsafe-v1.json");
const FIXTURE_SCHEMA_VERSION: u16 = 1;
const MAX_FIXTURE_BYTES: usize = 8 * 1024;
pub(super) const TARGET_OBSERVATION_ID: &str = "target-held-out-safe-v1";
pub(super) const TARGET_UNSAFE_OBSERVATION_ID: &str = "target-held-out-unsafe-v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetObservationTemplate {
    schema_version: u16,
    observation_id: String,
    task_score_delta: f64,
    candidate_safety_violations: u32,
    candidate_policy_violations: u32,
    replay_equivalence_passed: bool,
    sandbox_suite_passed: bool,
    invariant_suites: BTreeMap<String, bool>,
    reported_train_eval_overlap: bool,
}

pub(super) fn load(
    suite: &EvaluationSuite,
    baseline: &PolicyRef,
    candidate: &PolicyRef,
) -> Result<HeldOutEvalReport, TranscriptRunError> {
    load_template(
        SAFE_FIXTURE,
        TARGET_OBSERVATION_ID,
        0,
        suite,
        baseline,
        candidate,
    )
}

pub(super) fn load_unsafe(
    suite: &EvaluationSuite,
    baseline: &PolicyRef,
    candidate: &PolicyRef,
) -> Result<HeldOutEvalReport, TranscriptRunError> {
    load_template(
        UNSAFE_FIXTURE,
        TARGET_UNSAFE_OBSERVATION_ID,
        1,
        suite,
        baseline,
        candidate,
    )
}

fn load_template(
    fixture: &[u8],
    observation_id: &str,
    expected_safety_violations: u32,
    suite: &EvaluationSuite,
    baseline: &PolicyRef,
    candidate: &PolicyRef,
) -> Result<HeldOutEvalReport, TranscriptRunError> {
    if fixture.len() > MAX_FIXTURE_BYTES {
        return Err(TranscriptRunError::Invariant(
            "target-model held-out observation fixture exceeds its byte limit",
        ));
    }
    let template: TargetObservationTemplate = serde_json::from_slice(fixture)?;
    if template.schema_version != FIXTURE_SCHEMA_VERSION
        || template.observation_id != observation_id
        || !template.task_score_delta.is_finite()
        || !(0.0..=0.5).contains(&template.task_score_delta)
        || template.candidate_safety_violations != expected_safety_violations
        || template.invariant_suites.is_empty()
        || template.invariant_suites.len() > MAX_INVARIANT_SUITES
    {
        return Err(TranscriptRunError::Invariant(
            "target-model held-out observation fixture is invalid",
        ));
    }

    let pairs = suite
        .tasks()
        .iter()
        .enumerate()
        .map(|(index, task)| HeldOutTaskPair {
            task_id: task.task_id.clone(),
            fixture_digest: task.fixture_digest.clone(),
            baseline: reward(0.5, 0, 0),
            candidate: reward(
                0.5 + template.task_score_delta,
                u32::from(index == 0) * template.candidate_safety_violations,
                u32::from(index == 0) * template.candidate_policy_violations,
            ),
        })
        .collect();
    Ok(HeldOutEvalReport {
        schema_version: crate::HELD_OUT_REPORT_SCHEMA_VERSION,
        baseline: baseline.clone(),
        candidate: candidate.clone(),
        pairs,
        intervals: HeldOutReportIntervals {
            task_score_delta: HeldOutMetricBounds {
                lower: template.task_score_delta,
                upper: template.task_score_delta,
            },
            cost_delta_usd: HeldOutMetricBounds {
                lower: 0.0,
                upper: 0.0,
            },
            latency_delta_ms: HeldOutMetricBounds {
                lower: 0.0,
                upper: 0.0,
            },
        },
        replay_equivalence_passed: template.replay_equivalence_passed,
        sandbox_suite_passed: template.sandbox_suite_passed,
        invariant_suites: template.invariant_suites,
        reported_train_eval_overlap: Some(template.reported_train_eval_overlap),
    })
}

fn reward(score: f64, safety_violations: u32, policy_violations: u32) -> RewardVector {
    RewardVector {
        task_score: score,
        correctness: score,
        safety_violations,
        policy_violations,
        cost_usd: 0.01,
        wall_time_ms: 10,
        human_acceptance: Some(score),
        domain: BTreeMap::new(),
    }
}
