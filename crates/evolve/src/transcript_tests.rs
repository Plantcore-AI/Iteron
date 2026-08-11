use super::*;
use crate::transcript_demo_support as demo;
use crate::{
    ArtifactKind, BaseModelId, DeploymentStage, EvolutionMethod, PromotionAuditKind,
    PromotionAuthority,
};

fn scratch(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "iteron-evolve-offline-transcript-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos()
    ))
}

fn records(path: &Path) -> Vec<TranscriptRecord> {
    std::fs::read_to_string(path)
        .expect("transcript is readable")
        .lines()
        .map(|line| serde_json::from_str(line).expect("record is valid JSON"))
        .collect()
}

fn model(id: &str, digest_seed: char) -> BaseModelId {
    BaseModelId {
        model_family: "configured/frozen".into(),
        model_id: id.into(),
        model_digest: digest_seed.to_string().repeat(64),
    }
}

#[test]
fn one_button_transcript_is_deterministic_and_replayable() {
    let first_root = scratch("determinism-a");
    let second_root = scratch("determinism-b");
    let first = run_offline_transcript(&first_root).expect("first run succeeds");
    let second = run_offline_transcript(&second_root).expect("second run succeeds");

    assert_eq!(
        std::fs::read(&first.transcript_path).unwrap(),
        std::fs::read(&second.transcript_path).unwrap()
    );
    assert_eq!(
        std::fs::read(&first.promotion_journal_path).unwrap(),
        std::fs::read(&second.promotion_journal_path).unwrap()
    );
    assert_eq!(
        std::fs::read(&first.target_promotion_journal_path).unwrap(),
        std::fs::read(&second.target_promotion_journal_path).unwrap()
    );
    assert_eq!(
        std::fs::read(&first.trajectory_registry_path).unwrap(),
        std::fs::read(&second.trajectory_registry_path).unwrap()
    );
    assert_eq!(
        verify_offline_transcript(&first.transcript_path).unwrap(),
        first.event_count
    );

    let promotion_root = first.promotion_journal_path.parent().unwrap();
    let mut reopened = PromotionAuthority::open(
        promotion_root,
        demo::AUTHORITY_ID,
        demo::control_policy(),
        vec![demo::promotion_anchor()],
        vec![demo::evaluator_anchor()],
    )
    .expect("promotion journal replays and verifies");
    let active = reopened.active_bundle().unwrap().unwrap();
    assert_eq!(active.bundle().digest, first.final_active_bundle_digest);
    let source_transferred_identity = reopened
        .audit()
        .unwrap()
        .into_iter()
        .find_map(|event| {
            matches!(event.kind, PromotionAuditKind::CandidateAdmitted).then(|| {
                let lineage = event.lineage.expect("candidate admission has lineage");
                (lineage.bundle_id, lineage.bundle_digest)
            })
        })
        .expect("source journal contains the transferred candidate");
    let target_promotion_root = first.target_promotion_journal_path.parent().unwrap();
    let mut reopened_target = PromotionAuthority::open(
        target_promotion_root,
        demo::TARGET_AUTHORITY_ID,
        demo::control_policy(),
        vec![demo::promotion_anchor()],
        vec![demo::evaluator_anchor()],
    )
    .expect("target promotion journal replays and verifies");
    let target_active = reopened_target.active_bundle().unwrap().unwrap();
    assert_eq!(
        target_active.bundle().digest,
        first.final_active_bundle_digest
    );
    let target_transferred_identity = reopened_target
        .audit()
        .unwrap()
        .into_iter()
        .find_map(|event| {
            matches!(event.kind, PromotionAuditKind::CandidateAdmitted).then(|| {
                let lineage = event.lineage.expect("candidate admission has lineage");
                (lineage.bundle_id, lineage.bundle_digest)
            })
        })
        .expect("target journal contains the transferred candidate");
    assert_eq!(source_transferred_identity.0, target_transferred_identity.0);
    assert_ne!(source_transferred_identity.1, target_transferred_identity.1);
    let first_records = records(&first.transcript_path);
    let registry_address = first_records
        .iter()
        .find_map(|record| match &record.event {
            TranscriptEvent::TrajectoryProjected {
                run_id,
                registry_address,
                ..
            } if run_id == "fixture-recorded-run" => Some(registry_address),
            _ => None,
        })
        .expect("trajectory event records the verified registry readback");
    assert_eq!(registry_address.len(), 64);
    assert!(
        registry_address
            .chars()
            .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
    );
    assert!(matches!(
        first_records.last().unwrap().event,
        TranscriptEvent::Completed { .. }
    ));

    std::fs::remove_dir_all(first_root).ok();
    std::fs::remove_dir_all(second_root).ok();
}

#[test]
fn portable_fraction_is_reported_not_offsetting() {
    let root = scratch("transfer");
    let result = run_offline_transcript(&root).unwrap();
    let transfer = records(&result.transcript_path)
        .into_iter()
        .find_map(|record| match record.event {
            TranscriptEvent::TransferReported {
                bundle_id,
                source_bundle_digest,
                target_bundle_digest,
                source_delta,
                target_delta,
                retained_delta,
                portable_fraction,
                target_gate_eligible,
                target_evaluation_fixture,
                ..
            } => Some((
                bundle_id,
                source_bundle_digest,
                target_bundle_digest,
                source_delta,
                target_delta,
                retained_delta,
                portable_fraction,
                target_gate_eligible,
                target_evaluation_fixture,
            )),
            _ => None,
        })
        .expect("transfer event exists");
    assert_eq!(transfer.0, "rule-model-a-bundle");
    for digest in [&transfer.1, &transfer.2] {
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .chars()
                .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
        );
    }
    assert_ne!(transfer.1, transfer.2);
    assert_eq!(
        (transfer.3, transfer.4, transfer.5, transfer.6, transfer.7),
        (0.125, 0.0625, 0.0625, 0.5, true)
    );
    assert_eq!(transfer.8, "target-held-out-safe-v1");
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn second_producer_roundtrips_full_pipeline() {
    let root = scratch("second-producer");
    let result = run_offline_transcript(&root).unwrap();
    let events: Vec<_> = records(&result.transcript_path)
        .into_iter()
        .map(|record| record.event)
        .collect();
    assert!(events.iter().any(|event| matches!(
        event,
        TranscriptEvent::CandidateProduced {
            label,
            method: EvolutionMethod::PreferenceOptimization,
            artifact_kind: ArtifactKind::Prompt,
            ..
        } if label == "prompt-model-a"
    )));
    for stage in [
        DeploymentStage::Shadow,
        DeploymentStage::Canary,
        DeploymentStage::Active,
    ] {
        assert!(events.iter().any(|event| matches!(
            event,
            TranscriptEvent::StageReached {
                label,
                stage: observed,
            } if label == "prompt-model-a" && *observed == stage
        )));
    }
    assert!(events.iter().any(|event| matches!(
        event,
        TranscriptEvent::RolledBack { label, .. } if label == "prompt-model-a"
    )));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn promotion_decision_is_independent_of_method_field() {
    let root = scratch("method-agnostic");
    let result = run_offline_transcript(&root).unwrap();
    let proof = records(&result.transcript_path)
        .into_iter()
        .find_map(|record| match record.event {
            TranscriptEvent::MethodAgnostic {
                first_method,
                first_artifact_kind,
                second_method,
                second_artifact_kind,
                matched_gate_input_digest,
                first_pipeline_path,
                second_pipeline_path,
                first_gate_refusal_reasons,
                second_gate_refusal_reasons,
                identical_gate_decision,
                byte_identical_gate_reasons,
            } => Some((
                first_method,
                first_artifact_kind,
                second_method,
                second_artifact_kind,
                matched_gate_input_digest,
                first_pipeline_path,
                second_pipeline_path,
                first_gate_refusal_reasons,
                second_gate_refusal_reasons,
                identical_gate_decision,
                byte_identical_gate_reasons,
            )),
            _ => None,
        })
        .expect("method-agnostic proof event exists");

    assert_eq!(proof.0, EvolutionMethod::Search);
    assert_eq!(proof.1, ArtifactKind::Rules);
    assert_eq!(proof.2, EvolutionMethod::PreferenceOptimization);
    assert_eq!(proof.3, ArtifactKind::Prompt);
    assert_eq!(proof.4.len(), 64);
    assert!(
        proof
            .4
            .chars()
            .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
    );
    assert_eq!(proof.5, proof.6);
    assert_eq!(
        proof.5,
        vec![
            "admit_held_out",
            "candidate_to_shadow",
            "shadow_refused",
            "shadow_to_canary",
            "canary_to_active",
            "active_to_rolled_back",
        ]
    );
    assert!(!proof.7.is_empty());
    assert_eq!(proof.7, proof.8);
    assert_eq!(
        serde_json::to_vec(&proof.7).unwrap(),
        serde_json::to_vec(&proof.8).unwrap()
    );
    assert!(proof.9);
    assert!(proof.10);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn producer_order_and_base_models_are_real_transcript_parameters() {
    let root = scratch("configured");
    let config = OfflineTranscriptConfig::new(
        model("configured-a", '3'),
        model("configured-b", '4'),
        TranscriptProducerKind::PromptPreference,
        TranscriptProducerKind::RuleSearch,
    )
    .unwrap();
    let result = run_offline_transcript_with_config(&root, &config).unwrap();
    let events: Vec<_> = records(&result.transcript_path)
        .into_iter()
        .map(|record| record.event)
        .collect();

    assert!(events.iter().any(|event| matches!(
        event,
        TranscriptEvent::CandidateProduced {
            label,
            method: EvolutionMethod::PreferenceOptimization,
            artifact_kind: ArtifactKind::Prompt,
            ..
        } if label == "prompt-configured-a"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        TranscriptEvent::CandidateProduced {
            label,
            method: EvolutionMethod::Search,
            artifact_kind: ArtifactKind::Rules,
            ..
        } if label == "rule-configured-a"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        TranscriptEvent::TransferReported {
            label,
            from_model,
            to_model,
            target_gate_eligible: true,
            ..
        } if label == "prompt-configured-a-to-configured-b"
            && from_model.as_ref() == config.source_base_model()
            && to_model.as_ref() == config.target_base_model()
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        TranscriptEvent::MethodAgnostic {
            first_method: EvolutionMethod::PreferenceOptimization,
            first_artifact_kind: ArtifactKind::Prompt,
            second_method: EvolutionMethod::Search,
            second_artifact_kind: ArtifactKind::Rules,
            identical_gate_decision: true,
            byte_identical_gate_reasons: true,
            ..
        }
    )));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn transcript_configuration_rejects_duplicate_producer_or_model() {
    let source = model("configured-a", '3');
    assert!(
        OfflineTranscriptConfig::new(
            source.clone(),
            source.clone(),
            TranscriptProducerKind::RuleSearch,
            TranscriptProducerKind::PromptPreference,
        )
        .is_err()
    );
    assert!(
        OfflineTranscriptConfig::new(
            source,
            model("configured-b", '4'),
            TranscriptProducerKind::RuleSearch,
            TranscriptProducerKind::RuleSearch,
        )
        .is_err()
    );
}

#[test]
fn transcript_records_independent_signer_candidate_stage_and_target_refusals() {
    let root = scratch("negative-rows");
    let result = run_offline_transcript(&root).unwrap();
    let events: Vec<_> = records(&result.transcript_path)
        .into_iter()
        .map(|record| record.event)
        .collect();

    for (label, reason) in [
        (
            "producer-anchor-held-out-signer",
            "independent_evaluator_required_by_authority",
        ),
        ("unsafe-rule", "candidate_safety_violation"),
    ] {
        assert!(events.iter().any(|event| matches!(
            event,
            TranscriptEvent::CandidateRefused {
                label: observed_label,
                reason: observed_reason,
            } if observed_label == label && observed_reason == reason
        )));
    }
    assert!(events.iter().any(|event| matches!(
        event,
        TranscriptEvent::CandidateRefused { reason, .. }
            if reason == "stage_safety_violation"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        TranscriptEvent::TransferReported {
            label,
            target_gate_eligible: false,
            target_evaluation_fixture,
            ..
        } if label == "rule-model-a-to-model-b-unsafe"
            && target_evaluation_fixture == "target-held-out-unsafe-v1"
    )));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn transcript_tampering_is_detected() {
    let root = scratch("tamper");
    let result = run_offline_transcript(&root).unwrap();
    let mut bytes = std::fs::read(&result.transcript_path).unwrap();
    let offset = bytes
        .iter()
        .position(|byte| *byte == b'e')
        .expect("fixture contains a mutable byte");
    bytes[offset] = b'f';
    std::fs::write(&result.transcript_path, bytes).unwrap();
    assert!(verify_offline_transcript(&result.transcript_path).is_err());
    std::fs::remove_dir_all(root).ok();
}
