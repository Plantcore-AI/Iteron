use super::model::{ComparisonViewV1, ParetoViewV1, display};
use super::{LabFactsV1, chain};
use crate::client_effects::workspace_storage::NativeDirectory;
use iteron_eval::evidence_bundle::{
    EvidenceBundleError, EvidenceBundleSource, EvidenceRowOutcome,
    verify_evidence_bundle_from_source,
};
use std::cell::Cell;
const MAX_TOTAL_READ: usize = 64 * 1024 * 1024;
const MAX_FILE_READ: usize = 32 * 1024 * 1024;
struct Source {
    directory: NativeDirectory,
    remaining: Cell<usize>,
}
impl EvidenceBundleSource for Source {
    fn names(&self) -> Result<Vec<String>, EvidenceBundleError> {
        let (entries, truncated) = self
            .directory
            .list(17)
            .map_err(|_| EvidenceBundleError::Digest)?;
        if truncated || entries.iter().any(|(_, is_dir)| *is_dir) {
            return Err(EvidenceBundleError::Digest);
        }
        Ok(entries.into_iter().map(|(name, _)| name).collect())
    }
    fn read(&self, name: &str, max: u64) -> Result<Vec<u8>, EvidenceBundleError> {
        let limit = usize::try_from(max)
            .map_err(|_| EvidenceBundleError::Digest)?
            .min(MAX_FILE_READ)
            .min(self.remaining.get());
        let bytes = self
            .directory
            .read(name, limit)
            .map_err(|_| EvidenceBundleError::Digest)?;
        self.remaining.set(
            self.remaining
                .get()
                .checked_sub(bytes.len())
                .ok_or(EvidenceBundleError::Digest)?,
        );
        Ok(bytes)
    }
}
pub(super) fn compare(
    root: &NativeDirectory,
    bundle: &str,
    key: &str,
) -> Result<LabFactsV1, &'static str> {
    let directory = chain(root, &[".iteron", "experiments", "evidence", bundle], false)
        .map_err(|_| "evidence namespace is unsafe")?
        .ok_or("no local evidence bundle exists")?;
    let source = Source {
        directory,
        remaining: Cell::new(MAX_TOTAL_READ),
    };
    let verified = verify_evidence_bundle_from_source(&source, key)
        .map_err(|_| "signed evidence or its bounded native source did not verify")?;
    let comparison = &verified.paired.comparison;
    let rows = &verified.evidence_rows.rows;
    let count = |kind| rows.iter().filter(|row| row.outcome == kind).count();
    let view = ComparisonViewV1 {
        bundle: display(bundle),
        synthetic: verified.is_synthetic_fixture(),
        baseline: display(&comparison.baseline.name),
        candidate: display(&comparison.treatment.name),
        baseline_rate: comparison.baseline.resolved_rate,
        candidate_rate: comparison.treatment.resolved_rate,
        rate_delta: comparison.resolved_rate_delta,
        ci95: comparison.paired_ci95,
        matched: comparison.matched_pairs,
        minimum: comparison.minimum_pairs,
        conclusion: comparison.statistical_conclusion.to_string(),
        signer_display: format!("{}…", &verified.index.public_key[..12]),
        cost_delta_usd: comparison.cost_delta_usd,
        total_rows: rows.len(),
        success: count(EvidenceRowOutcome::Success),
        task_failure: count(EvidenceRowOutcome::TaskFailure),
        infrastructure_failure: count(EvidenceRowOutcome::InfrastructureFailure),
        censored: count(EvidenceRowOutcome::Censored),
        held_out: rows
            .iter()
            .filter(|row| row.partition == iteron_eval::Partition::HeldOut)
            .count(),
        pareto: verified
            .pareto
            .points
            .iter()
            .map(|point| ParetoViewV1 {
                candidate: display(&point.candidate_id),
                resolved_rate: point.resolved_rate,
                average_cost_usd: point.average_cost_usd,
                average_latency_ms: point.average_latency_ms,
                failed: point.failed_runs,
            })
            .collect(),
        frontier: verified
            .pareto
            .frontier
            .iter()
            .map(|id| display(id))
            .collect(),
    };
    Ok(LabFactsV1::Comparison { view })
}
