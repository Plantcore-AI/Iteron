//! Bounded, offline-only conditional TPE and successive-halving coordinator.

use crate::types::{CostStatus, EvaluationManifest, EvaluationPurpose, Partition, RunStatus};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

mod journal;
mod state_ops;
use journal::TunerJournal;
use state_ops::{apply_event, digest, initial_state, result_order, tpe_score, validate_spec};

pub const MAX_TUNER_TRIALS: u16 = 256;
pub const MAX_TUNER_CONCURRENCY: u16 = 64;
const MAX_CANDIDATES: usize = 256;
const MAX_FAMILIES_PER_CANDIDATE: usize = 64;
const MAX_SPEC_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunerCandidate {
    pub id: String,
    /// Missing families are deliberately meaningful: TPE scores only the active conditional
    /// branch instead of inventing values for inactive families.
    pub values: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunerSpec {
    pub schema_version: u8,
    pub experiment_id: String,
    pub train_dataset_digest: String,
    pub tunables_registry_digest: String,
    pub max_trials: u16,
    pub max_concurrency: u16,
    pub reduction_factor: u8,
    /// Monotonically increasing resource budgets; each entry is one halving round.
    pub round_budgets: Vec<u32>,
    pub candidates: Vec<TunerCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialRequest {
    pub trial_id: String,
    pub candidate: TunerCandidate,
    pub candidate_digest: String,
    pub round: u8,
    pub budget: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialResult {
    pub trial_id: String,
    pub candidate_id: String,
    pub round: u8,
    pub resolved_rate: f64,
    pub average_cost_usd: Option<f64>,
    pub average_latency_ms: f64,
    pub manifest_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunerStatus {
    Running,
    AwaitingInflightResolution,
    RoundReady,
    Completed,
    TrialBudgetExhausted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunerSnapshot {
    pub experiment_id: String,
    pub round: u8,
    pub eligible_candidates: Vec<String>,
    pub inflight_trials: Vec<String>,
    pub results: Vec<TrialResult>,
    pub selected_candidate: Option<String>,
    pub trials_issued: u16,
    pub max_trials: u16,
    pub journal_head: String,
    pub status: TunerStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TunerEvent {
    Initialized { spec_digest: String },
    TrialIssued { request: TrialRequest },
    TrialAbandoned { trial_id: String },
    ObservationRecorded { result: TrialResult },
    RoundAdvanced { round: u8, survivors: Vec<String> },
    Completed { selected_candidate: String },
}

#[derive(Debug, thiserror::Error)]
pub enum TunerError {
    #[error("invalid tuner specification: {0}")]
    InvalidSpec(String),
    #[error("invalid tuner transition: {0}")]
    InvalidTransition(String),
    #[error("tuner journal is invalid: {0}")]
    Journal(String),
    #[error("evaluation manifest is not an exact tune/train observation: {0}")]
    TrainIsolation(String),
    #[error("cannot encode tuner state: {0}")]
    Encode(String),
}

#[derive(Debug, Clone)]
pub(super) struct TunerState {
    round: u8,
    eligible: Vec<String>,
    inflight: BTreeMap<String, TrialRequest>,
    results: Vec<TrialResult>,
    selected: Option<String>,
    issued: u16,
}

pub struct OfflineTuner {
    spec: TunerSpec,
    state: TunerState,
    journal: TunerJournal,
}

impl OfflineTuner {
    pub fn create(spec: TunerSpec, journal_path: &Path) -> Result<Self, TunerError> {
        validate_spec(&spec)?;
        let spec_digest = digest(&spec)?;
        let mut journal = TunerJournal::create(journal_path)?;
        let event = TunerEvent::Initialized {
            spec_digest: spec_digest.clone(),
        };
        journal.append(&event)?;
        Ok(Self {
            state: initial_state(&spec),
            spec,
            journal,
        })
    }

    pub fn open(spec: TunerSpec, journal_path: &Path) -> Result<Self, TunerError> {
        validate_spec(&spec)?;
        let spec_digest = digest(&spec)?;
        let (journal, events) = TunerJournal::open(journal_path)?;
        let mut state = initial_state(&spec);
        if events.first()
            != Some(&TunerEvent::Initialized {
                spec_digest: spec_digest.clone(),
            })
        {
            return Err(TunerError::Journal(
                "journal was initialized for a different tuner specification".into(),
            ));
        }
        for event in events.iter().skip(1) {
            apply_event(&spec, &mut state, event)?;
        }
        Ok(Self {
            spec,
            state,
            journal,
        })
    }

    pub fn issue_trials(&mut self) -> Result<Vec<TrialRequest>, TunerError> {
        if self.state.selected.is_some() {
            return Ok(Vec::new());
        }
        let available = usize::from(self.spec.max_concurrency)
            .saturating_sub(self.state.inflight.len())
            .min(usize::from(
                self.spec.max_trials.saturating_sub(self.state.issued),
            ));
        if available == 0 {
            return Ok(Vec::new());
        }
        let mut candidates = self.pending_candidates();
        candidates.sort_by(|left, right| self.suggestion_order(left, right));
        let mut issued = Vec::new();
        for candidate_id in candidates.into_iter().take(available) {
            let candidate = self
                .spec
                .candidates
                .iter()
                .find(|candidate| candidate.id == candidate_id)
                .expect("validated candidate identity")
                .clone();
            let request = TrialRequest {
                trial_id: format!("trial-{:04}", self.state.issued.saturating_add(1)),
                candidate_digest: digest(&candidate)?,
                candidate,
                round: self.state.round,
                budget: self.spec.round_budgets[usize::from(self.state.round)],
            };
            self.commit(TunerEvent::TrialIssued {
                request: request.clone(),
            })?;
            issued.push(request);
        }
        Ok(issued)
    }

    pub fn abandon_inflight(&mut self, trial_id: &str) -> Result<(), TunerError> {
        self.commit(TunerEvent::TrialAbandoned {
            trial_id: trial_id.into(),
        })
    }

    pub fn record_manifest(
        &mut self,
        trial_id: &str,
        manifest: &EvaluationManifest,
        arm: &str,
    ) -> Result<TrialResult, TunerError> {
        let request = self
            .state
            .inflight
            .get(trial_id)
            .ok_or_else(|| TunerError::InvalidTransition("trial is not in flight".into()))?;
        if manifest.purpose != EvaluationPurpose::Tune
            || manifest.dataset_digest != self.spec.train_dataset_digest
            || manifest.bundle_digest.as_deref() != Some(request.candidate_digest.as_str())
            || manifest
                .cells
                .iter()
                .any(|cell| cell.partition != Partition::Train)
        {
            return Err(TunerError::TrainIsolation(
                "held-out/test or mismatched training data cannot enter tuner feedback".into(),
            ));
        }
        let cells = manifest
            .cells
            .iter()
            .filter(|cell| cell.config == arm)
            .collect::<Vec<_>>();
        if cells.is_empty() {
            return Err(TunerError::TrainIsolation("selected arm is missing".into()));
        }
        let completed = cells
            .iter()
            .filter(|cell| cell.run_status == RunStatus::Completed)
            .count();
        let resolved = cells
            .iter()
            .filter(|cell| cell.run_status == RunStatus::Completed && cell.resolved == Some(true))
            .count();
        let priced = cells.iter().all(|cell| {
            cell.cost_status == CostStatus::Known
                && cell
                    .cost_usd
                    .is_some_and(|value| value.is_finite() && value >= 0.0)
        });
        let result = TrialResult {
            trial_id: trial_id.into(),
            candidate_id: request.candidate.id.clone(),
            round: request.round,
            resolved_rate: if completed == 0 {
                0.0
            } else {
                resolved as f64 / completed as f64
            },
            average_cost_usd: priced.then(|| {
                cells.iter().filter_map(|cell| cell.cost_usd).sum::<f64>() / cells.len() as f64
            }),
            average_latency_ms: cells.iter().map(|cell| cell.elapsed_ms as f64).sum::<f64>()
                / cells.len() as f64,
            manifest_digest: digest(manifest)?,
        };
        self.commit(TunerEvent::ObservationRecorded {
            result: result.clone(),
        })?;
        Ok(result)
    }

    pub fn advance_round(&mut self) -> Result<Option<String>, TunerError> {
        if !self.state.inflight.is_empty() || !self.pending_candidates().is_empty() {
            return Err(TunerError::InvalidTransition(
                "round cannot advance with pending or in-flight candidates".into(),
            ));
        }
        let mut ranked = self.current_results();
        ranked.sort_by(result_order);
        if ranked.is_empty() {
            return Err(TunerError::InvalidTransition(
                "round has no completed observations".into(),
            ));
        }
        if usize::from(self.state.round) + 1 == self.spec.round_budgets.len() {
            let selected = ranked[0].candidate_id.clone();
            self.commit(TunerEvent::Completed {
                selected_candidate: selected.clone(),
            })?;
            return Ok(Some(selected));
        }
        let keep = ranked
            .len()
            .div_ceil(usize::from(self.spec.reduction_factor));
        let survivors = ranked
            .into_iter()
            .take(keep)
            .map(|result| result.candidate_id.clone())
            .collect::<Vec<_>>();
        self.commit(TunerEvent::RoundAdvanced {
            round: self.state.round.saturating_add(1),
            survivors,
        })?;
        Ok(None)
    }

    pub fn snapshot(&self) -> TunerSnapshot {
        let pending = self.pending_candidates();
        let status = if self.state.selected.is_some() {
            TunerStatus::Completed
        } else if self.state.issued == self.spec.max_trials && !pending.is_empty() {
            TunerStatus::TrialBudgetExhausted
        } else if !self.state.inflight.is_empty() {
            TunerStatus::AwaitingInflightResolution
        } else if pending.is_empty() {
            TunerStatus::RoundReady
        } else {
            TunerStatus::Running
        };
        TunerSnapshot {
            experiment_id: self.spec.experiment_id.clone(),
            round: self.state.round,
            eligible_candidates: self.state.eligible.clone(),
            inflight_trials: self.state.inflight.keys().cloned().collect(),
            results: self.state.results.clone(),
            selected_candidate: self.state.selected.clone(),
            trials_issued: self.state.issued,
            max_trials: self.spec.max_trials,
            journal_head: self.journal.head_hash().into(),
            status,
        }
    }

    fn commit(&mut self, event: TunerEvent) -> Result<(), TunerError> {
        let mut next = self.state.clone();
        apply_event(&self.spec, &mut next, &event)?;
        self.journal.append(&event)?;
        self.state = next;
        Ok(())
    }

    fn pending_candidates(&self) -> Vec<String> {
        self.state
            .eligible
            .iter()
            .filter(|candidate| {
                !self
                    .state
                    .inflight
                    .values()
                    .any(|trial| &trial.candidate.id == *candidate)
                    && !self.state.results.iter().any(|result| {
                        &result.candidate_id == *candidate && result.round == self.state.round
                    })
            })
            .cloned()
            .collect()
    }

    fn current_results(&self) -> Vec<&TrialResult> {
        self.state
            .results
            .iter()
            .filter(|result| result.round == self.state.round)
            .collect()
    }

    fn suggestion_order(&self, left: &str, right: &str) -> Ordering {
        let completed = self.current_results();
        if completed.len() < 4 {
            return left.cmp(right);
        }
        let mut ranked = completed;
        ranked.sort_by(result_order);
        let good_count = ranked.len().div_ceil(5).max(1);
        let good = &ranked[..good_count];
        let bad = &ranked[good_count..];
        tpe_score(&self.spec, left, good, bad)
            .partial_cmp(&tpe_score(&self.spec, right, good, bad))
            .unwrap_or(Ordering::Equal)
            .reverse()
            .then_with(|| left.cmp(right))
    }
}

#[cfg(test)]
mod tests;
