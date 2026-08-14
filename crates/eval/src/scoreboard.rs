//! Deterministic evidence-only scoreboard generation.
//!
//! The public entry point accepts only a signed bundle directory plus its trusted Ed25519 key.
//! There is intentionally no public constructor from handwritten rates or counts.

use crate::evidence_bundle::{
    EvidenceBundleError, EvidenceRowOutcome, EvidenceRowsDocument, EvidenceRowsProvenance,
    VerifiedEvidenceBundle, verify_evidence_bundle,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const SCOREBOARD_SCHEMA_VERSION: u8 = 1;
pub const SCOREBOARD_SCHEMA_ID: &str = "iteron-eval/evidence-scoreboard/v1";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EvidenceScoreRow {
    candidate_id: String,
    total_rows: u64,
    resolved_denominator: u64,
    success: u64,
    task_failure: u64,
    infrastructure_failure: u64,
    censored: u64,
    held_out: u64,
    resolved_rate: Option<f64>,
    resolved_rate_ci95: Option<[f64; 2]>,
}

impl EvidenceScoreRow {
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    pub fn total_rows(&self) -> u64 {
        self.total_rows
    }

    pub fn resolved_denominator(&self) -> u64 {
        self.resolved_denominator
    }

    pub fn success(&self) -> u64 {
        self.success
    }

    pub fn task_failure(&self) -> u64 {
        self.task_failure
    }

    pub fn infrastructure_failure(&self) -> u64 {
        self.infrastructure_failure
    }

    pub fn censored(&self) -> u64 {
        self.censored
    }

    pub fn held_out(&self) -> u64 {
        self.held_out
    }

    pub fn resolved_rate(&self) -> Option<f64> {
        self.resolved_rate
    }

    pub fn resolved_rate_ci95(&self) -> Option<[f64; 2]> {
        self.resolved_rate_ci95
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EvidenceScoreboard {
    schema_version: u8,
    schema_id: String,
    bundle_index_sha256: String,
    trusted_signer: String,
    provenance: EvidenceRowsProvenance,
    publishable_measured_result: bool,
    rows: Vec<EvidenceScoreRow>,
}

impl EvidenceScoreboard {
    pub fn bundle_index_sha256(&self) -> &str {
        &self.bundle_index_sha256
    }

    pub fn trusted_signer(&self) -> &str {
        &self.trusted_signer
    }

    pub fn provenance(&self) -> EvidenceRowsProvenance {
        self.provenance
    }

    pub fn publishable_measured_result(&self) -> bool {
        self.publishable_measured_result
    }

    pub fn rows(&self) -> &[EvidenceScoreRow] {
        &self.rows
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScoreboardError {
    #[error("scoreboard requires a verified signed evidence bundle: {0}")]
    Evidence(#[from] EvidenceBundleError),
    #[error("scoreboard evidence has no candidate rows")]
    Empty,
}

/// Verify a strict signed bundle and only then derive scoreboard numbers. Measured rows are
/// recomputed from attested manifests by the verifier; signed synthetic rows remain explicitly
/// non-publishable. Handwritten rows/rates have no public path into this API.
pub fn generate_evidence_scoreboard(
    bundle_directory: &Path,
    trusted_public_key: &str,
) -> Result<EvidenceScoreboard, ScoreboardError> {
    let verified = verify_evidence_bundle(bundle_directory, trusted_public_key)?;
    score_verified_bundle(&verified)
}

fn score_verified_bundle(
    verified: &VerifiedEvidenceBundle,
) -> Result<EvidenceScoreboard, ScoreboardError> {
    score_rows(
        &verified.index.index_sha256,
        &verified.index.public_key,
        &verified.evidence_rows,
    )
}

fn score_rows(
    bundle_index_sha256: &str,
    trusted_signer: &str,
    evidence: &EvidenceRowsDocument,
) -> Result<EvidenceScoreboard, ScoreboardError> {
    evidence.validate()?;
    let mut grouped = BTreeMap::<&str, [u64; 5]>::new();
    for row in &evidence.rows {
        let counts = grouped.entry(&row.candidate_id).or_default();
        let index = match row.outcome {
            EvidenceRowOutcome::Success => 0,
            EvidenceRowOutcome::TaskFailure => 1,
            EvidenceRowOutcome::InfrastructureFailure => 2,
            EvidenceRowOutcome::Censored => 3,
        };
        counts[index] = counts[index].saturating_add(1);
        if row.partition == crate::types::Partition::HeldOut {
            counts[4] = counts[4].saturating_add(1);
        }
    }
    if grouped.is_empty() {
        return Err(ScoreboardError::Empty);
    }
    let rows = grouped
        .into_iter()
        .map(
            |(
                candidate_id,
                [
                    success,
                    task_failure,
                    infrastructure_failure,
                    censored,
                    held_out,
                ],
            )| {
                let resolved_denominator = success.saturating_add(task_failure);
                let resolved_rate = (resolved_denominator != 0)
                    .then(|| success as f64 / resolved_denominator as f64);
                EvidenceScoreRow {
                    candidate_id: candidate_id.into(),
                    total_rows: success
                        .saturating_add(task_failure)
                        .saturating_add(infrastructure_failure)
                        .saturating_add(censored),
                    resolved_denominator,
                    success,
                    task_failure,
                    infrastructure_failure,
                    censored,
                    held_out,
                    resolved_rate,
                    resolved_rate_ci95: resolved_rate
                        .map(|_| crate::statistics::wilson_interval(success, resolved_denominator)),
                }
            },
        )
        .collect();
    Ok(EvidenceScoreboard {
        schema_version: SCOREBOARD_SCHEMA_VERSION,
        schema_id: SCOREBOARD_SCHEMA_ID.into(),
        bundle_index_sha256: bundle_index_sha256.into(),
        trusted_signer: trusted_signer.into(),
        provenance: evidence.provenance,
        publishable_measured_result: evidence.provenance == EvidenceRowsProvenance::Measured,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn exact_frozen_fixture_reports_denominator_failures_interval_and_non_result_marker() {
        let board = generate_evidence_scoreboard(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/evidence-bundle-v1"),
            "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
        )
        .unwrap();
        assert_eq!(board.provenance(), EvidenceRowsProvenance::SyntheticFixture);
        assert!(!board.publishable_measured_result());
        let row = &board.rows()[0];
        assert_eq!(row.total_rows(), 4);
        assert_eq!(row.resolved_denominator(), 3);
        assert_eq!(row.success(), 2);
        assert_eq!(row.task_failure(), 1);
        assert_eq!(row.infrastructure_failure(), 1);
        assert_eq!(row.censored(), 0);
        assert_eq!(row.held_out(), 1);
        assert_eq!(row.resolved_rate(), Some(2.0 / 3.0));
        let [low, high] = row.resolved_rate_ci95().unwrap();
        assert!(low < 2.0 / 3.0 && high > 2.0 / 3.0);
    }

    #[test]
    fn public_generator_rejects_an_unsigned_handwritten_directory() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "iteron-scoreboard-unsigned-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("observations.json"),
            br#"{"resolved_rate":1.0,"denominator":1}"#,
        )
        .unwrap();
        assert!(matches!(
            generate_evidence_scoreboard(&root, &"0".repeat(64)),
            Err(ScoreboardError::Evidence(_))
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
