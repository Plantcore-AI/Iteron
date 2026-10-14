//! Session namespace and discovery. Paths remain rebuildable beside the authoritative rollout.
use crate::{RecordError, validate_run_id, validated_run_path};
use iteron_protocol::RunId;
use std::path::{Path, PathBuf};

pub(super) const MICROUSD_PER_USD: f64 = 1_000_000.0;

/// Projection timestamps are cache metadata, not chain state, so a pre-epoch clock reads as the
/// epoch rather than failing the projection.
const PRE_EPOCH_TIMESTAMP_SECS: u64 = 0;

/// Legacy floating-point ceilings are compatibility data only. Rounding down is deliberately
/// conservative: reconstructing old journals must never grant one extra micro-dollar.
pub(super) fn legacy_usd_to_microusd_floor(value: f64) -> u64 {
    let scaled =
        value * iteron_tunables::param_f64("record.session.microusd_per_usd", MICROUSD_PER_USD);
    if !scaled.is_finite() || scaled >= u64::MAX as f64 {
        u64::MAX
    } else {
        scaled.floor() as u64
    }
}

pub(super) fn rollout_path(runs_dir: &Path, run: &RunId) -> Result<PathBuf, RecordError> {
    validated_run_path(runs_dir, run, ".jsonl")
}

pub(super) fn per_run_meta_path(runs_dir: &Path, run: &RunId) -> Result<PathBuf, RecordError> {
    validated_run_path(runs_dir, run, ".meta.json")
}

/// The run ids of every rollout file in `runs_dir` (the ground truth of which runs exist).
pub(super) fn rollout_run_ids(runs_dir: &Path) -> Vec<RunId> {
    let mut ids = Vec::new();
    let Ok(rd) = std::fs::read_dir(runs_dir) else {
        return ids;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("jsonl") {
            continue;
        }
        if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
            let run = RunId(stem.to_string());
            if validate_run_id(&run).is_ok() {
                ids.push(run);
            }
        }
    }
    ids
}

pub(super) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(iteron_tunables::param_integer(
            "record.session.pre_epoch_timestamp_secs",
            PRE_EPOCH_TIMESTAMP_SECS,
        ))
}
