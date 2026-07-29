//! Direct method-agnostic gate proof for the offline transcript.

use crate::dataset::sha256_hex;
use crate::{
    BaseModelId, DeploymentStage, Interval, ProducedPolicyCandidate, PromotionAssessment,
    PromotionAuditEvent, PromotionAuditKind, PromotionEvidence, PromotionGate, TranscriptEvent,
    TranscriptRunError,
};
use serde::Serialize;
use std::collections::BTreeMap;

pub(super) fn prove(
    first: &ProducedPolicyCandidate,
    second: &ProducedPolicyCandidate,
    first_evidence: &PromotionEvidence,
    second_evidence: &PromotionEvidence,
    audit: &[PromotionAuditEvent],
    first_bundle_id: &str,
    second_bundle_id: &str,
) -> Result<TranscriptEvent, TranscriptRunError> {
    let first_method = first.manifest().method;
    let first_artifact_kind = first.manifest().artifact_kind;
    let second_method = second.manifest().method;
    let second_artifact_kind = second.manifest().artifact_kind;
    if first_method == second_method || first_artifact_kind == second_artifact_kind {
        return Err(TranscriptRunError::Invariant(
            "method-agnostic proof requires distinct producer method and artifact kind",
        ));
    }
    if first_evidence.candidate != first.manifest().policy
        || second_evidence.candidate != second.manifest().policy
    {
        return Err(TranscriptRunError::Invariant(
            "method-agnostic proof evidence is not bound to both real producer outputs",
        ));
    }

    // The identities differ because these are real outputs from distinct producers. Every input
    // the gate actually consumes must nevertheless match. A hard-constraint violation makes the
    // reasons non-empty, so equality cannot pass vacuously on two eligible decisions.
    let mut first_gate_evidence = first_evidence.clone();
    first_gate_evidence.candidate_safety_violations =
        first_gate_evidence.candidate_safety_violations.max(1);
    let mut second_gate_evidence = second_evidence.clone();
    second_gate_evidence.candidate_safety_violations =
        second_gate_evidence.candidate_safety_violations.max(1);
    let first_gate_input = serde_json::to_vec(&gate_input(&first_gate_evidence))?;
    let second_gate_input = serde_json::to_vec(&gate_input(&second_gate_evidence))?;
    if first_gate_input != second_gate_input {
        return Err(TranscriptRunError::Invariant(
            "real producer evidence differs on a promotion-gate input",
        ));
    }

    let gate = PromotionGate::default();
    let first_assessment = gate.assess(DeploymentStage::Candidate, &first_gate_evidence);
    let second_assessment = gate.assess(DeploymentStage::Candidate, &second_gate_evidence);
    let first_gate_refusal_reasons = refusal_reasons(&first_assessment)?;
    let second_gate_refusal_reasons = refusal_reasons(&second_assessment)?;
    let first_reason_bytes = serde_json::to_vec(&first_gate_refusal_reasons)?;
    let second_reason_bytes = serde_json::to_vec(&second_gate_refusal_reasons)?;
    let byte_identical_gate_reasons = first_reason_bytes == second_reason_bytes;
    let identical_gate_decision = first_assessment == second_assessment;
    if !identical_gate_decision || !byte_identical_gate_reasons {
        return Err(TranscriptRunError::Invariant(
            "promotion gate decision or refusal-reason bytes depended on producer metadata",
        ));
    }
    let first_pipeline_path = pipeline_path(audit, first_bundle_id);
    let second_pipeline_path = pipeline_path(audit, second_bundle_id);
    let expected_path = [
        "admit_held_out",
        "candidate_to_shadow",
        "shadow_refused",
        "shadow_to_canary",
        "canary_to_active",
        "active_to_rolled_back",
    ];
    if first_pipeline_path != expected_path || second_pipeline_path != expected_path {
        return Err(TranscriptRunError::Invariant(
            "producer candidates did not traverse the same complete promotion-authority path",
        ));
    }

    Ok(TranscriptEvent::MethodAgnostic {
        first_method,
        first_artifact_kind,
        second_method,
        second_artifact_kind,
        matched_gate_input_digest: sha256_hex(&first_gate_input),
        first_pipeline_path,
        second_pipeline_path,
        first_gate_refusal_reasons,
        second_gate_refusal_reasons,
        identical_gate_decision,
        byte_identical_gate_reasons,
    })
}

#[derive(Serialize)]
struct GateInput<'a> {
    base_model: &'a BaseModelId,
    same_strategy_slot: bool,
    paired_tasks: u64,
    task_score_delta: Interval,
    cost_delta_usd: Interval,
    latency_delta_ms: Interval,
    candidate_safety_violations: u64,
    candidate_policy_violations: u64,
    train_eval_overlap: bool,
    replay_equivalence_passed: bool,
    sandbox_suite_passed: bool,
    invariant_suites: &'a BTreeMap<String, bool>,
}

fn gate_input(evidence: &PromotionEvidence) -> GateInput<'_> {
    GateInput {
        base_model: &evidence.base_model,
        same_strategy_slot: evidence.baseline.slot == evidence.candidate.slot,
        paired_tasks: evidence.paired_tasks,
        task_score_delta: evidence.task_score_delta,
        cost_delta_usd: evidence.cost_delta_usd,
        latency_delta_ms: evidence.latency_delta_ms,
        candidate_safety_violations: evidence.candidate_safety_violations,
        candidate_policy_violations: evidence.candidate_policy_violations,
        train_eval_overlap: evidence.train_eval_overlap,
        replay_equivalence_passed: evidence.replay_equivalence_passed,
        sandbox_suite_passed: evidence.sandbox_suite_passed,
        invariant_suites: &evidence.invariant_suites,
    }
}

fn pipeline_path(audit: &[PromotionAuditEvent], bundle_id: &str) -> Vec<String> {
    audit
        .iter()
        .filter(|event| {
            event
                .lineage
                .as_ref()
                .is_some_and(|lineage| lineage.bundle_id == bundle_id)
        })
        .filter_map(|event| match &event.kind {
            PromotionAuditKind::CandidateAdmitted => Some("admit_held_out".into()),
            PromotionAuditKind::StageTransition { from, to, .. } => {
                Some(format!("{}_to_{}", stage_name(*from), stage_name(*to)))
            }
            PromotionAuditKind::StageRefused { stage, .. } => {
                Some(format!("{}_refused", stage_name(*stage)))
            }
            PromotionAuditKind::RolledBack { from, .. } => {
                Some(format!("{}_to_rolled_back", stage_name(*from)))
            }
            PromotionAuditKind::Bootstrapped { .. } => None,
        })
        .collect()
}

fn stage_name(stage: DeploymentStage) -> &'static str {
    match stage {
        DeploymentStage::Candidate => "candidate",
        DeploymentStage::Shadow => "shadow",
        DeploymentStage::Canary => "canary",
        DeploymentStage::Active => "active",
        DeploymentStage::Retired => "retired",
        DeploymentStage::RolledBack => "rolled_back",
    }
}

fn refusal_reasons(assessment: &PromotionAssessment) -> Result<Vec<String>, TranscriptRunError> {
    match assessment {
        PromotionAssessment::Reject { reasons } if !reasons.is_empty() => Ok(reasons.clone()),
        _ => Err(TranscriptRunError::Invariant(
            "method-agnostic proof requires nonempty gate refusal reasons",
        )),
    }
}
