//! Bounded, offline-only conditional TPE and successive-halving coordinator.

use crate::evidence_bundle::{
    EvidenceRowOutcome, EvidenceRowsDocument, EvidenceRowsProvenance, VerifiedEvidenceBundle,
    emit_candidate_evidence_rows,
};
use crate::trainer_bridge::TrainerBridgeSpec;
use crate::types::{CostStatus, EvaluationManifest, EvaluationPurpose, Partition};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

mod activation;
mod candidate_graph;
mod journal;
mod state_ops;
pub(crate) use activation::{MaterializedActivation, materialize_activation};
pub use candidate_graph::{
    CANDIDATE_GRAPH_SCHEMA_ID, CANDIDATE_GRAPH_SCHEMA_VERSION, CandidateAddress,
    CandidateAddressKind, CandidateCondition, CandidateDimension, CandidateExecutionDependency,
    CandidateExecutionNode, CandidateExperiment, CandidateGraph, CandidateGraphIdentity,
    CandidateLineage, CandidateMaterialization, CandidateNodeClass, CandidateOwnerKind,
    CandidatePatch, CandidateProductionPlan, CandidateSelectorKind, CandidateTopologyEdge,
    MAX_CANDIDATE_TOPOLOGY_EDGES,
};
use journal::TunerJournal;
use state_ops::{apply_event, digest, initial_state, rank_results, tpe_score, validate_spec};

pub(crate) fn tuning_candidate_features(candidate: &TunerCandidate) -> BTreeMap<String, String> {
    state_ops::candidate_features(candidate)
}

pub const MAX_TUNER_TRIALS: u16 = 256;
pub const MAX_TUNER_CONCURRENCY: u16 = 64;
const MAX_CANDIDATES: usize = 256;
/// A candidate must be able to express a whole-registry configuration. Deriving this from the
/// family count rather than pinning a literal means growing the registry cannot silently re-cap
/// candidates at a number smaller than the space they are searching.
const MAX_FAMILIES_PER_CANDIDATE: usize = iteron_tunables::EXPECTED_FAMILY_COUNT;
/// Upper bound over families, Tier-2 parameters, text artifacts and implementation bindings. It is
/// intentionally above the current registry total so registry growth cannot silently make a full
/// candidate inexpressible before the bound is revised.
pub const MAX_UNIVERSAL_CANDIDATE_DIMENSIONS: usize = 4_096;
pub const LEGACY_UNIVERSAL_CANDIDATE_SCHEMA_VERSION: u16 = 2;
pub const UNIVERSAL_CANDIDATE_SCHEMA_VERSION: u16 = CANDIDATE_GRAPH_SCHEMA_VERSION;
/// Current implementation lifecycle protocol. Version 2 is required for state transfer/HMR.
pub const IMPLEMENTATION_PROTOCOL: &str = "iteron-implementation/2";
/// Stateless replay compatibility for candidate schemas v1/v2.
pub const LEGACY_IMPLEMENTATION_PROTOCOL: &str = "iteron-implementation/1";
const MAX_SPEC_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateImplementation {
    pub module: iteron_tunables::ModuleId,
    pub implementation_id: String,
    pub protocol: String,
    /// Absolute path to the trusted marketplace catalog used to mint this implementation.
    pub catalog_path: String,
    /// Absolute root containing the catalog-addressed implementation artifact.
    pub artifact_root: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunerCandidate {
    /// Universal candidate wire schema. Version 3 uses the closed `graph` address space.
    pub schema_version: u16,
    pub id: String,
    /// Legacy schema-v1 family features. Schema v2 uses `profile` as its one canonical value
    /// address space and requires this map to be empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub values: BTreeMap<String, serde_json::Value>,
    /// Exact externally runnable candidate: Tier-1 values, Tier-2 parameters and prompt/tool text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<iteron_tunables::ProfileDocument>,
    /// Replaceable implementations selected for this candidate. Source paths and content digests
    /// are bound here; admission, authority, loading, and lifecycle remain host responsibilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub implementations: Vec<CandidateImplementation>,
    /// Canonical v3 graph. Legacy values/profile/implementations must be absent when this exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<CandidateGraph>,
}

impl TunerCandidate {
    /// Validate the versioned universal candidate shape shared by native and external trainers.
    pub fn validate_universal(&self) -> Result<(), TunerError> {
        state_ops::validate_universal_candidate(self)
    }

    /// Canonical content identity over profile values and implementation bindings together.
    pub fn digest_sha256(&self) -> Result<String, TunerError> {
        digest(self)
    }

    /// Render the canonical profile consumed by ordinary Iteron CLI and external harnesses.
    /// Implementation artifacts remain separate because loading code and installing values have
    /// different admission authorities.
    pub fn rendered_profile(&self) -> Result<(String, String), TunerError> {
        let materialized;
        let profile = if self.schema_version == CANDIDATE_GRAPH_SCHEMA_VERSION {
            materialized = self.materialize()?;
            &materialized.profile
        } else {
            self.profile.as_ref().ok_or_else(|| {
                TunerError::InvalidSpec("candidate has no universal profile document".into())
            })?
        };
        iteron_tunables::validate_profile(profile)
            .map_err(|error| TunerError::InvalidSpec(error.to_string()))?;
        let rendered = iteron_tunables::render_profile(profile)
            .map_err(|error| TunerError::Encode(error.to_string()))?;
        let digest = iteron_tunables::document_digest(&rendered);
        Ok((rendered, digest))
    }

    /// Deterministically expand the v3 graph into every runtime-addressed output.
    pub fn materialize(&self) -> Result<CandidateMaterialization, TunerError> {
        if self.schema_version != CANDIDATE_GRAPH_SCHEMA_VERSION {
            return Err(TunerError::InvalidSpec(
                "only iteron-candidate/3 has graph materialization".into(),
            ));
        }
        self.graph
            .as_ref()
            .ok_or_else(|| TunerError::InvalidSpec("schema v3 candidate needs a graph".into()))?
            .materialize(self)
    }

    pub fn graph_identity(&self) -> Result<Option<CandidateGraphIdentity>, TunerError> {
        if self.schema_version == CANDIDATE_GRAPH_SCHEMA_VERSION {
            return self.materialize()?.graph_identity().map(Some);
        }
        Ok(None)
    }

    pub fn implementation_bindings(&self) -> &[CandidateImplementation] {
        self.graph
            .as_ref()
            .map_or(self.implementations.as_slice(), |graph| {
                graph.implementations.as_slice()
            })
    }

    pub fn candidate_schema_id(&self) -> &'static str {
        match self.schema_version {
            1 => "iteron-candidate/1",
            LEGACY_UNIVERSAL_CANDIDATE_SCHEMA_VERSION => "iteron-candidate/2",
            CANDIDATE_GRAPH_SCHEMA_VERSION => CANDIDATE_GRAPH_SCHEMA_ID,
            _ => "iteron-candidate/unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunerSpec {
    pub schema_version: u8,
    pub experiment_id: String,
    pub train_dataset_digest: String,
    pub tunables_registry_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param_registry_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_text_registry_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trainer_bridge: Option<TrainerBridgeSpec>,
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
    /// Legacy end-to-end cell latency, including evaluator/oracle work.
    pub average_latency_ms: f64,
    /// Agent-process latency when the manifest supplies complete v4+ measurements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_agent_latency_ms: Option<f64>,
    /// Mean provider-accounted tokens per attempted cell. Missing usage remains `None` and ranks
    /// behind complete measurements; it is never treated as zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_tokens: Option<f64>,
    /// Content-free behavioral diagnosis aggregated only when every selected cell carried typed
    /// stream evidence. It never outranks resolved rate, measured tokens, latency, or cost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimization: Option<TrialOptimizationSummary>,
    pub manifest_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialOptimizationSummary {
    /// Mean provider-independent inference turns per attempted cell. Older tuner journals may not
    /// carry this additive signal and remain `None` instead of being misread as zero turns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_turns: Option<f64>,
    pub average_tool_calls: f64,
    pub average_tool_error_rate: f64,
    pub average_peak_tool_concurrency: f64,
    pub average_context_tokens_per_turn: f64,
    pub average_peak_context_tokens: f64,
    pub average_transcript_tokens_reclaimed: f64,
    /// Mean typed transcript-decrease observations per attempted cell. This is useful for tuning
    /// compaction frequency without claiming that every decrease came from one implementation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_transcript_shrink_events: Option<f64>,
    /// Mean source-separated tokens per sampled request. Absent for pre-v6 CLI evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_context_components_per_turn: Option<TrialContextComponentAverages>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialContextComponentAverages {
    pub stable_prefix: f64,
    pub instructions: f64,
    pub task_context: f64,
    pub memory: f64,
    pub transcript: f64,
    pub attachments: f64,
    pub tool_schemas: f64,
    pub tool_results: f64,
    pub lsp_results: f64,
}

impl TrialContextComponentAverages {
    fn from_metrics(
        metrics: &[crate::types::OptimizationMetrics],
        context_samples: u64,
    ) -> Option<Self> {
        let cumulative = metrics.iter().try_fold(
            crate::types::ContextComponentTokens::default(),
            |total, metric| total.checked_add(metric.context_components?.cumulative),
        )?;
        let samples = context_samples as f64;
        Some(Self {
            stable_prefix: cumulative.stable_prefix as f64 / samples,
            instructions: cumulative.instructions as f64 / samples,
            task_context: cumulative.task_context as f64 / samples,
            memory: cumulative.memory as f64 / samples,
            transcript: cumulative.transcript as f64 / samples,
            attachments: cumulative.attachments as f64 / samples,
            tool_schemas: cumulative.tool_schemas as f64 / samples,
            tool_results: cumulative.tool_results as f64 / samples,
            lsp_results: cumulative.lsp_results as f64 / samples,
        })
    }

    fn is_valid(self) -> bool {
        [
            self.stable_prefix,
            self.instructions,
            self.task_context,
            self.memory,
            self.transcript,
            self.attachments,
            self.tool_schemas,
            self.tool_results,
            self.lsp_results,
        ]
        .into_iter()
        .all(|value| value.is_finite() && value >= 0.0)
    }
}

impl TrialOptimizationSummary {
    fn from_cells(cells: &[&crate::types::CellResult]) -> Option<Self> {
        if cells.is_empty() {
            return None;
        }
        let metrics = cells
            .iter()
            .map(|cell| cell.agent_metrics?.optimization)
            .collect::<Option<Vec<_>>>()?;
        let count = metrics.len() as f64;
        let completed_tools = metrics
            .iter()
            .map(|metric| metric.tool_calls_completed)
            .try_fold(0_u64, u64::checked_add)?;
        let tool_errors = metrics
            .iter()
            .map(|metric| metric.tool_errors)
            .try_fold(0_u64, u64::checked_add)?;
        let context_samples = metrics
            .iter()
            .map(|metric| metric.context_samples)
            .try_fold(0_u64, u64::checked_add)?;
        if context_samples == 0 {
            // A tool-only prefix or interrupted stream is useful diagnosis but cannot establish
            // context efficiency. Do not let absent turn samples masquerade as a measured zero.
            return None;
        }
        let cumulative_context = metrics
            .iter()
            .map(|metric| metric.cumulative_context_tokens)
            .try_fold(0_u64, u64::checked_add)?;
        let average_context_components_per_turn =
            TrialContextComponentAverages::from_metrics(&metrics, context_samples);
        Some(Self {
            average_turns: Some(context_samples as f64 / count),
            average_tool_calls: completed_tools as f64 / count,
            average_tool_error_rate: if completed_tools == 0 {
                0.0
            } else {
                tool_errors as f64 / completed_tools as f64
            },
            average_peak_tool_concurrency: metrics
                .iter()
                .map(|metric| metric.peak_tool_concurrency as f64)
                .sum::<f64>()
                / count,
            average_context_tokens_per_turn: cumulative_context as f64 / context_samples as f64,
            average_peak_context_tokens: metrics
                .iter()
                .map(|metric| metric.peak_context_tokens as f64)
                .sum::<f64>()
                / count,
            average_transcript_tokens_reclaimed: metrics
                .iter()
                .map(|metric| metric.transcript_tokens_reclaimed as f64)
                .sum::<f64>()
                / count,
            average_transcript_shrink_events: Some(
                metrics
                    .iter()
                    .map(|metric| metric.transcript_shrink_events as f64)
                    .sum::<f64>()
                    / count,
            ),
            average_context_components_per_turn,
        })
    }

    fn is_valid(self) -> bool {
        [
            self.average_tool_calls,
            self.average_tool_error_rate,
            self.average_peak_tool_concurrency,
            self.average_context_tokens_per_turn,
            self.average_peak_context_tokens,
            self.average_transcript_tokens_reclaimed,
        ]
        .into_iter()
        .all(|value| value.is_finite() && value >= 0.0)
            && [self.average_turns, self.average_transcript_shrink_events]
                .into_iter()
                .flatten()
                .all(|value| value.is_finite() && value >= 0.0)
            && self.average_tool_error_rate <= 1.0
            && self
                .average_context_components_per_turn
                .is_none_or(TrialContextComponentAverages::is_valid)
    }
}

/// Read-only acceptance result for a frozen evidence-row document. It deliberately carries the
/// fixture marker and has no conversion into a journal event or runtime activation type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunerEvidenceInspection {
    pub document_sha256: String,
    pub provenance: EvidenceRowsProvenance,
    pub train_rows: usize,
    pub held_out_rows: usize,
    pub feedback_eligible: bool,
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
    TrialIssued { request: Box<TrialRequest> },
    TrialAbandoned { trial_id: String },
    ObservationRecorded { result: Box<TrialResult> },
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
    #[error("evidence rows are invalid: {0}")]
    EvidenceRows(String),
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
    /// Validate and classify the shared evidence schema without mutating the tuner. Synthetic
    /// fixtures and held-out rows remain inspectable for acceptance/UI tests but are never marked
    /// feedback-eligible.
    pub fn inspect_evidence_rows(
        evidence: &EvidenceRowsDocument,
    ) -> Result<TunerEvidenceInspection, TunerError> {
        evidence
            .validate()
            .map_err(|error| TunerError::EvidenceRows(error.to_string()))?;
        let held_out_rows = evidence
            .rows
            .iter()
            .filter(|row| row.partition == Partition::HeldOut)
            .count();
        Ok(TunerEvidenceInspection {
            document_sha256: evidence.document_sha256.clone(),
            provenance: evidence.provenance,
            train_rows: evidence.rows.len().saturating_sub(held_out_rows),
            held_out_rows,
            feedback_eligible: evidence.provenance == EvidenceRowsProvenance::Measured
                && held_out_rows == 0,
        })
    }

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
                request: Box::new(request.clone()),
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
            .ok_or_else(|| TunerError::InvalidTransition("trial is not in flight".into()))?
            .clone();
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
        let evidence = emit_candidate_evidence_rows(manifest, &request.candidate.id, arm)
            .map_err(|error| TunerError::EvidenceRows(error.to_string()))?;
        let selected = manifest
            .cells
            .iter()
            .filter(|cell| cell.config == arm)
            .collect::<Vec<_>>();
        let average_tokens = selected
            .iter()
            .map(|cell| {
                cell.agent_metrics?
                    .total_tokens()
                    .map(|tokens| tokens as f64)
            })
            .collect::<Option<Vec<_>>>()
            .filter(|tokens| !tokens.is_empty())
            .map(|tokens| tokens.iter().sum::<f64>() / tokens.len() as f64);
        let average_agent_latency_ms = selected
            .iter()
            .map(|cell| cell.agent_metrics.map(|metrics| metrics.elapsed_ms as f64))
            .collect::<Option<Vec<_>>>()
            .filter(|latencies| !latencies.is_empty())
            .map(|latencies| latencies.iter().sum::<f64>() / latencies.len() as f64);
        let optimization = TrialOptimizationSummary::from_cells(&selected);
        self.record_evidence_document(
            trial_id,
            &evidence,
            average_tokens,
            average_agent_latency_ms,
            optimization,
        )
    }

    /// Record observations only from a verifier-minted bundle. The private seal on
    /// `VerifiedEvidenceBundle` prevents callers from constructing a handwritten substitute.
    pub fn record_verified_evidence(
        &mut self,
        trial_id: &str,
        bundle: &VerifiedEvidenceBundle,
    ) -> Result<TrialResult, TunerError> {
        bundle
            .validate_in_memory_seal()
            .map_err(|error| TunerError::EvidenceRows(error.to_string()))?;
        self.record_evidence_document(trial_id, &bundle.evidence_rows, None, None, None)
    }

    fn record_evidence_document(
        &mut self,
        trial_id: &str,
        evidence: &EvidenceRowsDocument,
        average_tokens: Option<f64>,
        average_agent_latency_ms: Option<f64>,
        optimization: Option<TrialOptimizationSummary>,
    ) -> Result<TrialResult, TunerError> {
        let inspection = Self::inspect_evidence_rows(evidence)?;
        if !inspection.feedback_eligible {
            return Err(TunerError::TrainIsolation(
                "synthetic fixture or held-out evidence cannot enter tuner feedback".into(),
            ));
        }
        let request = self
            .state
            .inflight
            .get(trial_id)
            .ok_or_else(|| TunerError::InvalidTransition("trial is not in flight".into()))?
            .clone();
        let rows = evidence
            .rows
            .iter()
            .filter(|row| row.run_id == trial_id && row.candidate_id == request.candidate.id)
            .collect::<Vec<_>>();
        if rows.is_empty()
            || rows.iter().any(|row| {
                row.partition != Partition::Train
                    || row.dataset_digest != self.spec.train_dataset_digest
                    || row.candidate_digest.as_deref() != Some(request.candidate_digest.as_str())
            })
        {
            return Err(TunerError::TrainIsolation(
                "held-out/test or mismatched training data cannot enter tuner feedback".into(),
            ));
        }
        let completed = rows
            .iter()
            .filter(|row| {
                matches!(
                    row.outcome,
                    EvidenceRowOutcome::Success | EvidenceRowOutcome::TaskFailure
                )
            })
            .count();
        let resolved = rows
            .iter()
            .filter(|row| row.outcome == EvidenceRowOutcome::Success)
            .count();
        let priced = rows.iter().all(|row| {
            row.cost_status == CostStatus::Known
                && row
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
                rows.iter().filter_map(|row| row.cost_usd).sum::<f64>() / rows.len() as f64
            }),
            average_latency_ms: rows.iter().map(|row| row.elapsed_ms as f64).sum::<f64>()
                / rows.len() as f64,
            average_agent_latency_ms,
            average_tokens,
            optimization,
            manifest_digest: evidence.document_sha256.clone(),
        };
        self.commit(TunerEvent::ObservationRecorded {
            result: Box::new(result.clone()),
        })?;
        Ok(result)
    }

    pub fn advance_round(&mut self) -> Result<Option<String>, TunerError> {
        if !self.state.inflight.is_empty() || !self.pending_candidates().is_empty() {
            return Err(TunerError::InvalidTransition(
                "round cannot advance with pending or in-flight candidates".into(),
            ));
        }
        let ranked = rank_results(&self.spec, self.current_results());
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
        let ranked = rank_results(&self.spec, completed);
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
