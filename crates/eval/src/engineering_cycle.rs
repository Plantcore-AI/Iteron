//! Provider-free synthetic harness evolution cycle.

use iteron_evolve::{
    BaseModelId, OfflineTranscriptConfig, TranscriptEvent, TranscriptProducerKind,
    TranscriptRecord, run_offline_transcript_with_config, verify_offline_transcript,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticCycleAuthorization {
    schema_id: String,
    authorization_id: String,
    authorized_by: String,
    authorization_scope: String,
    approval_artifact_path: String,
    approval_artifact_sha256: String,
    source_frozen_model: BaseModelId,
    target_frozen_model: BaseModelId,
    primary_producer: TranscriptProducerKind,
    secondary_producer: TranscriptProducerKind,
    provider: String,
    model_training_authorized: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SyntheticCycleReceipt {
    schema_id: &'static str,
    authorization_id: String,
    authorized_by: String,
    authorization_input_sha256: String,
    approval_artifact_sha256: String,
    provider: &'static str,
    provider_calls: u64,
    source_frozen_model: BaseModelId,
    target_frozen_model: BaseModelId,
    primary_producer: TranscriptProducerKind,
    secondary_producer: TranscriptProducerKind,
    trajectory_admitted: bool,
    governed_dataset_constructed: bool,
    candidate_produced: bool,
    candidate_admitted: bool,
    held_out_separation_observed: bool,
    stage_order_observed: bool,
    human_authorized_promotion_input_consumed: bool,
    activation_observed: bool,
    exact_rollback_observed: bool,
    final_active_bundle_digest: String,
    transcript_records: usize,
    transcript_sha256: String,
    model_training_performed: bool,
    live_score_claimed: bool,
}

/// Provider-free end-to-end harness evolution command. The authorization and approval artifacts
/// are operator-owned inputs; this command consumes them but never treats the public demo keys as
/// proof of a real-world person's identity. Activation is the authenticated offline promotion
/// pointer only, and the evolve pipeline must restore the exact baseline before return.
pub fn run_synthetic_cycle_cli(args: &[String]) -> ExitCode {
    let result = parse_synthetic_cycle_args(args)
        .and_then(|(authorization, output)| run_synthetic_cycle(&authorization, &output));
    match result {
        Ok(receipt) => match write_json_line(&receipt) {
            Ok(()) => ExitCode::SUCCESS,
            Err(()) => ExitCode::from(2),
        },
        Err(error) => {
            eprintln!("iteron synthetic cycle: {error}");
            ExitCode::from(2)
        }
    }
}

fn parse_synthetic_cycle_args(args: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let [authorization_flag, authorization, output_flag, output] = args else {
        return Err("expected --authorization FILE --output CREATE_NEW_DIRECTORY".to_owned());
    };
    if authorization_flag != "--authorization" || output_flag != "--output" {
        return Err("expected --authorization FILE --output CREATE_NEW_DIRECTORY".to_owned());
    }
    let authorization = PathBuf::from(authorization);
    let output = PathBuf::from(output);
    if !authorization.is_absolute() || !output.is_absolute() || output.file_name().is_none() {
        return Err("synthetic cycle paths must be absolute".into());
    }
    Ok((authorization, output))
}

fn run_synthetic_cycle(
    authorization_path: &Path,
    output: &Path,
) -> Result<SyntheticCycleReceipt, String> {
    if output.try_exists().map_err(|error| error.to_string())? {
        return Err("synthetic cycle output must be create-new".into());
    }
    let authorization_bytes = read_regular_bounded(authorization_path, 1024 * 1024)?;
    let authorization_value = crate::strict_json::parse_json_no_duplicates(&authorization_bytes)
        .map_err(|error| error.to_string())?;
    let authorization: SyntheticCycleAuthorization =
        serde_json::from_value(authorization_value).map_err(|error| error.to_string())?;
    if authorization.schema_id != "iteron-synthetic-cycle-authorization/1"
        || !valid_id(&authorization.authorization_id)
        || !valid_id(&authorization.authorized_by)
        || authorization.authorization_scope != "synthetic_harness_promotion_and_rollback"
        || authorization.provider != "none"
        || authorization.model_training_authorized
    {
        return Err("synthetic authorization is outside its closed scope".into());
    }
    let declared_approval = Path::new(&authorization.approval_artifact_path);
    if declared_approval.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err("approval artifact path cannot traverse directories".into());
    }
    let approval_path = if declared_approval.is_absolute() {
        declared_approval.to_path_buf()
    } else {
        authorization_path
            .parent()
            .ok_or_else(|| "authorization input has no parent".to_owned())?
            .join(declared_approval)
    };
    if approval_path == authorization_path {
        return Err("approval artifact must be a separate operator-owned input".into());
    }
    let approval = read_regular_bounded(&approval_path, 1024 * 1024)?;
    let approval_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&approval)));
    if approval.is_empty() || approval_sha256 != authorization.approval_artifact_sha256 {
        return Err("approval artifact does not match the authorization input".into());
    }
    let config = OfflineTranscriptConfig::new(
        authorization.source_frozen_model.clone(),
        authorization.target_frozen_model.clone(),
        authorization.primary_producer,
        authorization.secondary_producer,
    )
    .map_err(|error| error.to_string())?;
    let result =
        run_offline_transcript_with_config(output, &config).map_err(|error| error.to_string())?;
    let verified_records =
        verify_offline_transcript(&result.transcript_path).map_err(|error| error.to_string())?;
    let transcript = read_regular_bounded(&result.transcript_path, 16 * 1024 * 1024)?;
    let events = transcript
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice::<TranscriptRecord>(line)
                .map(|record| record.event)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if events.len() != verified_records || verified_records != result.event_count {
        return Err("synthetic transcript record counts did not correlate".into());
    }
    let trajectory_admitted = events
        .iter()
        .any(|event| matches!(event, TranscriptEvent::TrajectoryProjected { .. }));
    let governed_dataset_constructed = events.iter().any(
        |event| matches!(event, TranscriptEvent::DatasetRegistered { members, .. } if *members > 0),
    );
    let candidate_produced = events
        .iter()
        .any(|event| matches!(event, TranscriptEvent::CandidateProduced { .. }));
    let candidate_admitted = events
        .iter()
        .any(|event| matches!(event, TranscriptEvent::CandidateAdmitted { .. }));
    let active_labels = events
        .iter()
        .filter_map(|event| match event {
            TranscriptEvent::StageReached {
                label,
                stage: iteron_evolve::DeploymentStage::Active,
            } => Some(label.as_str()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let rollback_labels = events
        .iter()
        .filter_map(|event| match event {
            TranscriptEvent::RolledBack { label, .. } => Some(label.as_str()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let completed_digest = events.iter().find_map(|event| match event {
        TranscriptEvent::Completed {
            final_active_bundle_digest,
            ..
        } => Some(final_active_bundle_digest.as_str()),
        _ => None,
    });
    let activation_observed = !active_labels.is_empty();
    let exact_rollback_observed = active_labels.is_subset(&rollback_labels)
        && completed_digest == Some(result.final_active_bundle_digest.as_str());
    let held_out_separation_observed = candidate_admitted
        && events.iter().any(|event| {
            matches!(
                event,
                TranscriptEvent::CandidateRefused { label, reason }
                    if label.contains("held-out")
                        && reason.starts_with("independent_evaluator_required")
            )
        });
    let position = |predicate: fn(&TranscriptEvent) -> bool| events.iter().position(predicate);
    let ordered = [
        position(|event| matches!(event, TranscriptEvent::TrajectoryProjected { .. })),
        position(|event| matches!(event, TranscriptEvent::DatasetRegistered { .. })),
        position(|event| matches!(event, TranscriptEvent::CandidateProduced { .. })),
        position(|event| matches!(event, TranscriptEvent::CandidateAdmitted { .. })),
        position(|event| {
            matches!(
                event,
                TranscriptEvent::StageReached {
                    stage: iteron_evolve::DeploymentStage::Active,
                    ..
                }
            )
        }),
        position(|event| matches!(event, TranscriptEvent::RolledBack { .. })),
        position(|event| matches!(event, TranscriptEvent::Completed { .. })),
    ];
    let ordered = ordered
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .is_some_and(|positions| positions.windows(2).all(|pair| pair[0] < pair[1]));
    if !trajectory_admitted
        || !governed_dataset_constructed
        || !candidate_produced
        || !candidate_admitted
        || !held_out_separation_observed
        || !activation_observed
        || !exact_rollback_observed
        || !ordered
    {
        return Err("synthetic end-to-end evolution obligations were not all observed".into());
    }
    let authorization_input_sha256 = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(&authorization_bytes))
    );
    let receipt = SyntheticCycleReceipt {
        schema_id: "iteron-synthetic-harness-cycle/1",
        authorization_id: authorization.authorization_id,
        authorized_by: authorization.authorized_by,
        authorization_input_sha256,
        approval_artifact_sha256: approval_sha256,
        provider: "none",
        provider_calls: 0,
        source_frozen_model: authorization.source_frozen_model,
        target_frozen_model: authorization.target_frozen_model,
        primary_producer: authorization.primary_producer,
        secondary_producer: authorization.secondary_producer,
        trajectory_admitted,
        governed_dataset_constructed,
        candidate_produced,
        candidate_admitted,
        held_out_separation_observed,
        stage_order_observed: ordered,
        human_authorized_promotion_input_consumed: true,
        activation_observed,
        exact_rollback_observed,
        final_active_bundle_digest: result.final_active_bundle_digest,
        transcript_records: verified_records,
        transcript_sha256: format!("sha256:{}", hex::encode(Sha256::digest(&transcript))),
        model_training_performed: false,
        live_score_claimed: false,
    };
    let receipt_path = output.join("synthetic-cycle-receipt.json");
    let mut receipt_bytes =
        serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
    receipt_bytes.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&receipt_path)
        .map_err(|error| error.to_string())?;
    file.write_all(&receipt_bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(receipt)
}

fn read_regular_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("bounded input path is not absolute".into());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err("bounded input is not a regular non-symlink file".into());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err("bounded input changed while being read".into());
    }
    Ok(bytes)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
        })
}

fn write_json_line(value: &impl Serialize) -> Result<(), ()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| ())?;
    bytes.push(b'\n');
    std::io::stdout().lock().write_all(&bytes).map_err(|_| ())
}
