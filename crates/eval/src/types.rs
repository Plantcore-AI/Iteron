use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const EVAL_SCHEMA_VERSION: u32 = 6;

/// One provider-independent, non-overlapping context-source vector.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextComponentTokens {
    pub stable_prefix: u64,
    pub instructions: u64,
    pub task_context: u64,
    pub memory: u64,
    pub transcript: u64,
    pub attachments: u64,
    pub tool_schemas: u64,
    pub tool_results: u64,
    pub lsp_results: u64,
}

impl ContextComponentTokens {
    pub(crate) fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            stable_prefix: self.stable_prefix.checked_add(other.stable_prefix)?,
            instructions: self.instructions.checked_add(other.instructions)?,
            task_context: self.task_context.checked_add(other.task_context)?,
            memory: self.memory.checked_add(other.memory)?,
            transcript: self.transcript.checked_add(other.transcript)?,
            attachments: self.attachments.checked_add(other.attachments)?,
            tool_schemas: self.tool_schemas.checked_add(other.tool_schemas)?,
            tool_results: self.tool_results.checked_add(other.tool_results)?,
            lsp_results: self.lsp_results.checked_add(other.lsp_results)?,
        })
    }

    pub(crate) fn component_max(self, other: Self) -> Self {
        Self {
            stable_prefix: self.stable_prefix.max(other.stable_prefix),
            instructions: self.instructions.max(other.instructions),
            task_context: self.task_context.max(other.task_context),
            memory: self.memory.max(other.memory),
            transcript: self.transcript.max(other.transcript),
            attachments: self.attachments.max(other.attachments),
            tool_schemas: self.tool_schemas.max(other.tool_schemas),
            tool_results: self.tool_results.max(other.tool_results),
            lsp_results: self.lsp_results.max(other.lsp_results),
        }
    }
}

/// Complete source-separated evidence across all sampled turns of one run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextComponentMetrics {
    pub cumulative: ContextComponentTokens,
    pub peak: ContextComponentTokens,
    pub final_turn: ContextComponentTokens,
}

/// Content-free runtime behavior observed from the stable CLI event stream.
///
/// These are diagnostic optimization signals, not task-success substitutes. Ground-truth still
/// decides whether a candidate resolved the task; this record explains where equal-quality
/// candidates spent tool and context work. Every counter is derived from typed machine events,
/// never from model text, notices, provider identity, or a harness-specific log parser.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizationMetrics {
    pub tool_calls_started: u64,
    pub tool_calls_completed: u64,
    pub tool_errors: u64,
    pub peak_tool_concurrency: u64,
    pub context_samples: u64,
    /// Sum of per-turn request-context estimates. This is an area-under-context signal: repeatedly
    /// replaying a large prefix costs more than reaching the same peak once.
    pub cumulative_context_tokens: u64,
    pub peak_context_tokens: u64,
    pub final_context_tokens: Option<u64>,
    pub peak_system_tokens: u64,
    pub peak_tool_schema_tokens: u64,
    pub peak_transcript_tokens: u64,
    /// Typed transcript decreases between consecutive turn-end estimates. A decrease is evidence
    /// of reclaimed transcript, without claiming which runtime mechanism caused it.
    pub transcript_shrink_events: u64,
    pub transcript_tokens_reclaimed: u64,
    /// Present only when every observed turn carried the source-separated v6 context vector.
    /// Older stream versions remain readable and leave this absent rather than inventing zeros.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_components: Option<ContextComponentMetrics>,
}

/// Provider-independent work performed by the agent process itself.
///
/// `elapsed_ms` stops before repository diff collection and external oracle execution. Token
/// classes are disjoint except that `thinking` is an attribution subset of `output`, so it is
/// never added a second time by [`AgentMetrics::total_tokens`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMetrics {
    pub elapsed_ms: u64,
    pub usage: Option<iteron_protocol::Usage>,
    /// Present when the selected machine-output surface carried typed tool/context events. Legacy
    /// v4 manifests and final-result-only harnesses leave this absent rather than synthesizing
    /// zero behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimization: Option<OptimizationMetrics>,
}

impl AgentMetrics {
    pub fn total_tokens(self) -> Option<u64> {
        let usage = self.usage?;
        if usage.thinking > usage.output {
            return None;
        }
        usage
            .input
            .checked_add(usage.cache_creation)?
            .checked_add(usage.cache_read)?
            .checked_add(usage.output)
    }
}

#[cfg(test)]
mod agent_metrics_tests {
    use super::*;

    #[test]
    fn legacy_v4_agent_metrics_do_not_invent_optimization_evidence() {
        let metrics: AgentMetrics = serde_json::from_str(
            r#"{"elapsed_ms":17,"usage":{"input":3,"output":2,"cache_creation":0,"cache_read":0,"thinking":0}}"#,
        )
        .expect("the additive v5 field must preserve v4 manifest readability");

        assert_eq!(metrics.elapsed_ms, 17);
        assert_eq!(metrics.optimization, None);
        assert_eq!(metrics.total_tokens(), Some(5));
    }
}

/// Stable process exit codes for the `iteron-eval` binary.
///
/// The evaluation artifact is always persisted, but the process exit status must not silently
/// discard the run outcome: a completed-with-failures run and a clean run cannot both report
/// success. CI and operators rely on these codes to detect harness / infrastructure failures.
pub const EVAL_EXIT_SUCCESS: u8 = 0;
/// One or more cells failed to run under the harness — subprocess spawn / JSON-contract failures,
/// checkout failures, ground-truth infrastructure failures, or wall-clock timeouts. The manifest is
/// still written; this code makes the failed-run accounting visible in the exit status.
pub const EVAL_EXIT_RUN_FAILURES: u8 = 1;
/// The harness could not produce a manifest at all (`run_evaluation` returned an error).
pub const EVAL_EXIT_HARNESS: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Partition {
    Train,
    HeldOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationPurpose {
    Tune,
    Score,
}

impl EvaluationPurpose {
    pub fn required_partition(self) -> Partition {
        match self {
            Self::Tune => Partition::Train,
            Self::Score => Partition::HeldOut,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Completed,
    Errored,
    Censored,
    TimedOut,
}

impl RunStatus {
    pub fn enters_resolved_denominator(self) -> bool {
        self == Self::Completed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Passed,
    TestFailed,
    TimedOut,
    InfrastructureFailed,
    NotRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostStatus {
    Known,
    Zero,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkReference {
    pub name: String,
    pub instance_id: String,
    pub dataset_revision: String,
    pub environment_setup_commit: String,
    pub environment_image: Option<String>,
    pub test_patch_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostObservation {
    pub status: CostStatus,
    pub usd: Option<f64>,
    pub reason: Option<String>,
}

/// Separate harness-overhead line aggregated across evaluation cells.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelTaxObservation {
    pub admission_latency_us: u64,
    pub broker_latency_us: u64,
    pub record_fsync_latency_us: u64,
    pub estimated_tokens: u64,
    pub failed_runs: u64,
}

impl KernelTaxObservation {
    pub fn add(&mut self, other: Self) {
        self.admission_latency_us = self
            .admission_latency_us
            .saturating_add(other.admission_latency_us);
        self.broker_latency_us = self
            .broker_latency_us
            .saturating_add(other.broker_latency_us);
        self.record_fsync_latency_us = self
            .record_fsync_latency_us
            .saturating_add(other.record_fsync_latency_us);
        self.estimated_tokens = self.estimated_tokens.saturating_add(other.estimated_tokens);
        self.failed_runs = self.failed_runs.saturating_add(other.failed_runs);
    }
}

impl CostObservation {
    pub fn known(usd: f64) -> Self {
        Self {
            status: CostStatus::Known,
            usd: Some(usd),
            reason: None,
        }
    }

    pub fn zero() -> Self {
        Self {
            status: CostStatus::Zero,
            // Human reports render this as `zero`, never as a misleading priced `$0.0000` cell.
            usd: None,
            reason: None,
        }
    }

    pub fn unknown(reason: Option<String>) -> Self {
        Self {
            status: CostStatus::Unknown,
            usd: None,
            reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingControl {
    pub requested_seed: u64,
    pub enforcement: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwoSidedOracleReceipt {
    pub fail_to_pass_before: crate::provisioner::TestSetReceipt,
    pub pass_to_pass_before: crate::provisioner::TestSetReceipt,
    pub fail_to_pass_after: crate::provisioner::TestSetReceipt,
    pub pass_to_pass_after: crate::provisioner::TestSetReceipt,
    pub resolved: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CellKey<'a> {
    pub task: &'a str,
    pub config: &'a str,
    pub seed: u64,
    pub partition: Partition,
    pub repo_url: &'a str,
    pub commit: &'a str,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellResult {
    pub task: String,
    pub config: String,
    pub seed: u64,
    pub partition: Partition,
    pub repo_url: String,
    pub commit: String,
    pub benchmark: Option<BenchmarkReference>,
    pub resolved: Option<bool>,
    pub run_status: RunStatus,
    pub failure_phase: Option<String>,
    pub exit_code: Option<i32>,
    pub terminal_outcome: Option<String>,
    pub cost_status: CostStatus,
    pub cost_usd: Option<f64>,
    pub cost_reason: Option<String>,
    pub turns: Option<u32>,
    pub kernel_tax: Option<KernelTaxObservation>,
    pub oracle_status: OracleStatus,
    pub oracle_detail: Option<String>,
    pub sampling: SamplingControl,
    /// Exact agent-process measurements. Legacy v3 manifests deserialize this as unavailable;
    /// missing measurements can be inspected but cannot support a speed/token superiority claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_metrics: Option<AgentMetrics>,
    pub elapsed_ms: u64,
    pub error: Option<String>,
    pub candidate_diff: Option<String>,
}

impl CellResult {
    pub fn errored(key: CellKey<'_>, phase: &str, error: impl Into<String>) -> Self {
        Self {
            task: key.task.to_owned(),
            config: key.config.to_owned(),
            seed: key.seed,
            partition: key.partition,
            repo_url: key.repo_url.to_owned(),
            commit: key.commit.to_owned(),
            benchmark: None,
            resolved: None,
            run_status: RunStatus::Errored,
            failure_phase: Some(phase.to_owned()),
            exit_code: None,
            terminal_outcome: None,
            cost_status: CostStatus::Unknown,
            cost_usd: None,
            cost_reason: Some("harness_error".into()),
            turns: None,
            kernel_tax: None,
            oracle_status: OracleStatus::NotRun,
            oracle_detail: None,
            sampling: SamplingControl {
                requested_seed: key.seed,
                enforcement: "uncontrolled".into(),
                reason: Some("route exposes no sampling-seed contract".into()),
            },
            agent_metrics: None,
            elapsed_ms: 0,
            error: Some(error.into()),
            candidate_diff: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationManifest {
    pub schema_version: u32,
    pub run_id: String,
    pub corpus_version: String,
    pub dataset_digest: String,
    pub model: String,
    pub provider: Option<String>,
    /// SHA-256 of the immutable boot-time policy bundle, or `None` for the untrained/default arm.
    pub bundle_digest: Option<String>,
    pub purpose: EvaluationPurpose,
    pub seeds: u64,
    pub minimum_seeds: u64,
    pub workers: u16,
    /// `None` records an explicitly uncapped run. A capped run never uses zero.
    pub max_turns: Option<u32>,
    /// Inner wall-clock budget supplied to the Core agent.
    pub core_agent_wall_secs: u64,
    /// Bounded startup/finalization allowance owned by the evaluator, not by the agent.
    pub core_process_grace_secs: u64,
    /// Outer evaluator kill ceiling: `core_agent_wall_secs + core_process_grace_secs`.
    pub core_process_timeout_secs: u64,
    pub result_path: PathBuf,
    pub cells: Vec<CellResult>,
    pub aggregate: crate::report::Aggregate,
    pub comparison: crate::report::Comparison,
    pub selections: Vec<crate::report::SelectionSummary>,
    pub kernel_tax: KernelTaxObservation,
}

impl EvaluationManifest {
    /// Count cells whose run failed under the harness rather than reaching a terminal model
    /// outcome: subprocess spawn / JSON-contract failures, checkout failures, ground-truth
    /// infrastructure failures ([`RunStatus::Errored`]) and wall-clock timeouts
    /// ([`RunStatus::TimedOut`]).
    ///
    /// Censored runs ([`RunStatus::Censored`] — budget-exhausted, interrupted, or stuck) are
    /// legitimate model outcomes, not harness failures, and are deliberately excluded so a model
    /// that simply exhausts its turn budget does not mark the whole evaluation as broken.
    pub fn failed_runs(&self) -> u64 {
        self.cells
            .iter()
            .filter(|cell| matches!(cell.run_status, RunStatus::Errored | RunStatus::TimedOut))
            .count() as u64
    }

    /// Stable process exit code for the whole evaluation. Any failed run yields a non-zero status
    /// so the run outcome is not discarded behind an unconditional success.
    pub fn exit_code(&self) -> u8 {
        if self.failed_runs() > 0 {
            EVAL_EXIT_RUN_FAILURES
        } else {
            EVAL_EXIT_SUCCESS
        }
    }
}
