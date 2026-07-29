//! core-obs — the phase oracle and the attribution ledger.
//!
//! The harness is the only layer that knows what phase it is in, which makes it the only
//! layer that can be observed, attributed, and priced (the phase-oracle thesis, ADR-002).
//! This crate meters the things that make that real:
//!   - token usage BY CACHE CLASS (not one scalar) — the attribution substrate,
//!   - tool latency (`tau_wall` contribution) and how much overlapped decoding,
//!   - phase durations,
//!   - tool-error counts,
//!   - the cache-hit ratio per turn (the append-only-discipline health signal).
//!
//! Vertical slice: an in-memory ledger with a human summary. `tau_steps`, `RR(k)` curves,
//! and the OTel GenAI export are interface-present / TODO against ADR-002; the token/latency/
//! phase substrate they need is all collected here.

use core_protocol::{
    CostProjection, CostProjectionIdentity, MAX_WORKFLOW_COST_PROJECTIONS, SignedRateCard, Usage,
    WorkflowCostEvidence, WorkflowMetrics,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

mod metrics;
mod phase;
pub mod pricing;
pub use metrics::{EphemeralTimings, ReproducibleCounters, TimingSnapshot};
pub use phase::PhaseSpan;
pub use pricing::{
    HmacPricingAuthority, HmacPricingKey, MAX_TRUSTED_RATE_CARDS, PricingError, PricingPort,
    PricingReplay, sign_rate_card, validate_projection_digest, validate_rate_card_digest,
};

#[derive(Debug, PartialEq, Eq)]
pub enum ProjectionAdmissionError {
    Pricing(PricingError),
    Ledger(&'static str),
}

/// Authenticate one live signed projection through the injected trust port before it may advance
/// monetary ledger state. Digest validity alone is content integrity, not billing authority.
pub fn admit_verified_projection(
    pricing: &dyn PricingPort,
    rate_card: &SignedRateCard,
    expected_identity: &CostProjectionIdentity,
    projection: &CostProjection,
    ledger: &mut Ledger,
) -> Result<(), ProjectionAdmissionError> {
    if projection.identity.as_ref() != Some(expected_identity) {
        return Err(ProjectionAdmissionError::Pricing(
            if projection.identity.is_none() {
                PricingError::MissingProjectionIdentity
            } else {
                PricingError::ProjectionIdentityMismatch
            },
        ));
    }
    pricing
        .verify_projection(rate_card, projection)
        .map_err(ProjectionAdmissionError::Pricing)?;
    ledger
        .apply_cost_projection(projection)
        .map_err(ProjectionAdmissionError::Ledger)
}

/// Honest cumulative monetary state. Core does not infer billing from token counts without a
/// route-bound, versioned rate card and does not treat an attempt without usage as free.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CostState {
    /// No provider request has been admitted, so zero is provable.
    #[default]
    Zero,
    /// Every completed provider turn has a durable, route-bound pricing projection. Amounts are
    /// fixed-point micro-USD, never floating point.
    Known {
        amount_microusd: u64,
        rate_card_digest: String,
    },
    /// A dollar amount cannot be established from the durable evidence available to this run.
    Unknown { reason: CostUnknownReason },
}

impl CostState {
    pub fn usd(&self) -> Option<f64> {
        match self {
            Self::Zero => Some(0.0),
            Self::Known {
                amount_microusd, ..
            } => Some(*amount_microusd as f64 / 1_000_000.0),
            Self::Unknown { .. } => None,
        }
    }

    pub fn status(&self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::Known { .. } => "known",
            Self::Unknown { .. } => "unknown",
        }
    }

    pub fn reason(&self) -> Option<CostUnknownReason> {
        match self {
            Self::Unknown { reason } => Some(*reason),
            Self::Zero | Self::Known { .. } => None,
        }
    }

    pub fn human(&self) -> String {
        match self {
            Self::Zero => "$0.0000 (no provider requests)".into(),
            Self::Known { .. } => format!("${:.4}", self.usd().unwrap_or_default()),
            Self::Unknown { reason } => format!("unknown ({})", reason.label()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostUnknownReason {
    /// Precedence 3: completed turns exist, but no authenticated route-bound projection prices all
    /// of them. This is weaker than missing billing evidence or a legacy unattributed projection.
    NoVerifiedRateCard,
    /// Precedence 1: an admitted provider/child attempt has no terminal usage evidence. This
    /// includes a deliberately dropped or cancelled stream; it does not accuse the provider.
    BillingEvidenceMissing,
    /// Precedence 2: historical pricing bytes exist but predate rollout-bound projection identity.
    /// They remain readable and must never be relabelled as authenticated current-run cost.
    LegacyUnattributed,
    /// Precedence 0 (highest): fixed-point addition overflowed, so no lower-priority explanation
    /// can make the amount representable.
    AmountOverflow,
}

impl CostUnknownReason {
    /// Stable precedence rank; lower wins when several facts apply.
    pub const fn precedence(self) -> u8 {
        match self {
            Self::AmountOverflow => 0,
            Self::BillingEvidenceMissing => 1,
            Self::LegacyUnattributed => 2,
            Self::NoVerifiedRateCard => 3,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::NoVerifiedRateCard => "no_verified_rate_card",
            Self::BillingEvidenceMissing => "billing_evidence_missing",
            Self::LegacyUnattributed => "legacy_unattributed",
            Self::AmountOverflow => "amount_overflow",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::NoVerifiedRateCard => "no verified rate card",
            Self::BillingEvidenceMissing => "billing evidence missing for one or more attempts",
            Self::LegacyUnattributed => "legacy usage has no route/rate-card attribution",
            Self::AmountOverflow => "fixed-point amount exceeded its representable range",
        }
    }
}

/// Harness overhead kept separate from model latency and billable model tokens.
///
/// Latencies are measured at the actual admission, effect-broker bookkeeping, and durable append
/// boundaries. `estimated_tokens` is the deterministic system/tool/framing input estimate, never
/// presented as provider-tokenizer truth. `failed_runs` is attached at the terminal output edge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelTax {
    pub admission_latency_us: u64,
    pub broker_latency_us: u64,
    pub record_fsync_latency_us: u64,
    pub estimated_tokens: u64,
    pub failed_runs: u64,
}

impl KernelTax {
    pub fn with_failed_run(mut self, failed: bool) -> Self {
        self.failed_runs = u64::from(failed);
        self
    }

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

/// The running ledger for one run. Cheap to update on the hot path (ADR-002: the cost of
/// observability must stay below the cost of the thing observed).
#[derive(Debug, Default, Clone)]
pub struct Ledger {
    /// Logical provider calls admitted, including failed calls and merged child-agent attempts.
    /// `turns` below counts completed responses with usage; hard turn ceilings use attempts so a
    /// failing decomposition/compaction path cannot buy an extra request for free.
    pub provider_attempts: u32,
    pub turns: u32,
    /// Aggregate billable usage for this run, including merged child-agent ledgers.
    pub usage: Usage,
    /// Usage produced by provider turns admitted directly by this agent.
    pub local_usage: Usage,
    /// Usage attributed from child agents. Kept separate so cache health for the active transcript
    /// is never silently blended with unrelated child prefixes.
    pub child_usage: Usage,
    /// The most recently completed direct provider turn. `merge` deliberately does not overwrite
    /// it; a child finishing is not the parent's last model request.
    pub last_turn_usage: Option<Usage>,
    pub tool_calls: u64,
    pub tool_errors: u64,
    /// Pure-tool calls that could not acquire an early-dispatch slot and were routed to the
    /// bounded inline collection path instead. This is an admission-pressure signal, not an
    /// execution error.
    pub tool_inline_overflow_events: u64,
    /// Wall-clock is process-local and private so callers must acknowledge replay completeness
    /// through [`Self::timings`] instead of reading a plausible-looking restored zero.
    timings: EphemeralTimings,
    timing_history_unknown: bool,
    /// Completed turns for which a signed projection has been durably admitted.
    priced_turns: u32,
    amount_microusd: u64,
    amount_overflowed: bool,
    legacy_unattributed: bool,
    rate_card_digests: BTreeSet<String>,
    cost_projections: Vec<CostProjection>,
    /// Durable child admissions whose terminal accounting has not been observed. This is kept
    /// separate from provider attempts: a child may have crashed before dispatch, but it may also
    /// have spent money that the parent never received, so zero/Known is no longer provable.
    unresolved_child_attributions: u32,
    kernel_tax: KernelTax,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit one logical provider request. This is separate from `turn`, which is called only
    /// when the provider returns authoritative usage.
    pub fn attempt(&mut self) {
        self.provider_attempts = self.provider_attempts.saturating_add(1);
    }

    /// Stable, record-derived accounting with all ephemeral timing excluded by construction.
    pub fn reproducible_counters(&self) -> ReproducibleCounters {
        ReproducibleCounters {
            provider_attempts: self.provider_attempts,
            completed_turns: self.turns,
            usage: self.usage,
            tool_calls: self.tool_calls,
            tool_errors: self.tool_errors,
        }
    }

    pub fn kernel_tax(&self) -> KernelTax {
        self.kernel_tax
    }

    pub fn record_admission_latency_us(&mut self, elapsed_us: u64) {
        self.kernel_tax.admission_latency_us = self
            .kernel_tax
            .admission_latency_us
            .saturating_add(elapsed_us);
    }

    pub fn record_broker_latency_us(&mut self, elapsed_us: u64) {
        self.kernel_tax.broker_latency_us =
            self.kernel_tax.broker_latency_us.saturating_add(elapsed_us);
    }

    pub fn record_fsync_latency_us(&mut self, elapsed_us: u64) {
        self.kernel_tax.record_fsync_latency_us = self
            .kernel_tax
            .record_fsync_latency_us
            .saturating_add(elapsed_us);
    }

    pub fn record_kernel_tokens(&mut self, estimated_tokens: u64) {
        self.kernel_tax.estimated_tokens = self
            .kernel_tax
            .estimated_tokens
            .saturating_add(estimated_tokens);
    }

    pub(crate) fn mark_legacy_unattributed(&mut self) {
        self.legacy_unattributed = true;
    }

    /// Process-local timing with an explicit completeness marker.
    pub fn timings(&self) -> TimingSnapshot {
        if self.timing_history_unknown {
            TimingSnapshot::UnknownAfterReplay {
                observed_partial: self.timings,
            }
        } else {
            TimingSnapshot::Complete(self.timings)
        }
    }

    /// Replay can reconstruct counters, but not every historical phase duration. Clear any
    /// process-local values and make that missing history absorbing for subsequent merges.
    pub(crate) fn mark_timing_unknown_after_replay(&mut self) {
        if !self.timing_history_unknown {
            self.timings = EphemeralTimings::default();
            self.timing_history_unknown = true;
        }
    }

    pub(crate) fn admit_child_attribution(&mut self) {
        self.unresolved_child_attributions = self.unresolved_child_attributions.saturating_add(1);
    }

    pub(crate) fn resolve_child_attribution(&mut self) {
        self.unresolved_child_attributions = self.unresolved_child_attributions.saturating_sub(1);
    }

    /// Record a completed model turn's usage by cache class.
    pub fn turn(&mut self, usage: &Usage, model_ms: u64) {
        self.turns = self.turns.saturating_add(1);
        self.usage.add(usage);
        self.local_usage.add(usage);
        self.last_turn_usage = Some(*usage);
        self.timings.phase_model_ms = self.timings.phase_model_ms.saturating_add(model_ms);
    }

    /// Restore a completed provider turn from durable usage without inventing model wall time.
    pub(crate) fn replay_turn(&mut self, usage: &Usage) {
        self.turns = self.turns.saturating_add(1);
        self.usage.add(usage);
        self.local_usage.add(usage);
        self.last_turn_usage = Some(*usage);
    }

    /// Record model time for a successful response whose provider omitted authoritative usage.
    ///
    /// This intentionally does not increment `turns` or add a synthetic zero [`Usage`]. The
    /// preceding [`Self::attempt`] therefore remains unmatched, which makes [`Self::cost_state`]
    /// report `BillingEvidenceMissing` and prevents a known-zero dollar result.
    pub fn turn_without_usage(&mut self, model_ms: u64) {
        self.last_turn_usage = None;
        self.timings.phase_model_ms = self.timings.phase_model_ms.saturating_add(model_ms);
    }

    /// Bind a signed, content-addressed price to the immediately preceding completed turn. The
    /// live kernel calls this only after the projection event is durable; replay calls it only
    /// after checking the projection digest and route/card binding.
    pub(crate) fn apply_cost_projection(
        &mut self,
        projection: &CostProjection,
    ) -> Result<(), &'static str> {
        pricing::validate_projection_digest(projection)
            .map_err(|_| "invalid pricing projection digest")?;
        if self.priced_turns >= self.turns {
            return Err("pricing projection has no unpriced completed turn");
        }
        if self.last_turn_usage != Some(projection.usage) {
            return Err("pricing projection usage does not match the completed turn");
        }
        self.priced_turns = self.priced_turns.saturating_add(1);
        if let Some(amount) = self.amount_microusd.checked_add(projection.amount_microusd) {
            self.amount_microusd = amount;
        } else {
            self.amount_overflowed = true;
        }
        self.rate_card_digests
            .insert(projection.rate_card_digest.clone());
        self.cost_projections.push(projection.clone());
        Ok(())
    }

    /// Attribute a child-agent ledger to its owning run. Child rollouts remain separate for
    /// replay, but their provider spend and work must still count against the operator's budget.
    pub fn merge(&mut self, child: &Ledger) {
        self.provider_attempts = self
            .provider_attempts
            .saturating_add(child.provider_attempts);
        self.turns = self.turns.saturating_add(child.turns);
        self.usage.add(&child.usage);
        self.child_usage.add(&child.usage);
        self.timings.merge(child.timings);
        self.timing_history_unknown |= child.timing_history_unknown;
        self.tool_calls = self.tool_calls.saturating_add(child.tool_calls);
        self.tool_errors = self.tool_errors.saturating_add(child.tool_errors);
        self.tool_inline_overflow_events = self
            .tool_inline_overflow_events
            .saturating_add(child.tool_inline_overflow_events);
        self.priced_turns = self.priced_turns.saturating_add(child.priced_turns);
        if let Some(amount) = self.amount_microusd.checked_add(child.amount_microusd) {
            self.amount_microusd = amount;
        } else {
            self.amount_overflowed = true;
        }
        self.amount_overflowed |= child.amount_overflowed;
        self.legacy_unattributed |= child.legacy_unattributed;
        self.kernel_tax.add(child.kernel_tax);
        self.rate_card_digests
            .extend(child.rate_card_digests.iter().cloned());
        self.cost_projections
            .extend(child.cost_projections.iter().cloned());
        self.unresolved_child_attributions = self
            .unresolved_child_attributions
            .saturating_add(child.unresolved_child_attributions);
    }

    /// Content-free attribution snapshot suitable for the parent workflow journal. Child rollouts
    /// keep full messages; the parent needs only additive accounting to make resume and session
    /// projection preserve the same hard ceilings as the live run.
    pub fn workflow_metrics(&self) -> WorkflowMetrics {
        let complete_timings = (!self.timing_history_unknown).then_some(self.timings);
        WorkflowMetrics {
            provider_attempts: self.provider_attempts,
            completed_turns: self.turns,
            usage: self.usage,
            tool_calls: self.tool_calls,
            tool_errors: self.tool_errors,
            model_ms: complete_timings.map(|timings| timings.phase_model_ms),
            tools_ms: complete_timings.map(|timings| timings.phase_tools_ms),
            cost: self.workflow_cost_evidence(),
        }
    }

    /// Metrics attributable to work after `baseline`. Workflow terminal cards use this delta so a
    /// follow-up does not relabel the whole session's historical usage as the latest workflow.
    pub fn workflow_metrics_since(&self, baseline: &Ledger) -> WorkflowMetrics {
        let completed_turns = self.turns.saturating_sub(baseline.turns);
        let priced_turns = self.priced_turns.saturating_sub(baseline.priced_turns);
        let projections = self
            .cost_projections
            .get(baseline.cost_projections.len()..)
            .unwrap_or_default()
            .to_vec();
        let delta_rate_card_digests = projections
            .iter()
            .map(|projection| projection.rate_card_digest.clone())
            .collect::<BTreeSet<_>>();
        let cost = (completed_turns > 0
            && priced_turns == completed_turns
            && !self.amount_overflowed
            && !baseline.amount_overflowed
            && self.unresolved_child_attributions == 0
            && baseline.unresolved_child_attributions == 0)
            .then(|| WorkflowCostEvidence {
                amount_microusd: self
                    .amount_microusd
                    .saturating_sub(baseline.amount_microusd),
                rate_card_digest: combined_rate_card_digest(&delta_rate_card_digests),
                projections,
            });
        WorkflowMetrics {
            provider_attempts: self
                .provider_attempts
                .saturating_sub(baseline.provider_attempts),
            completed_turns,
            usage: Usage {
                input: self.usage.input.saturating_sub(baseline.usage.input),
                output: self.usage.output.saturating_sub(baseline.usage.output),
                cache_creation: self
                    .usage
                    .cache_creation
                    .saturating_sub(baseline.usage.cache_creation),
                cache_read: self
                    .usage
                    .cache_read
                    .saturating_sub(baseline.usage.cache_read),
                thinking: self.usage.thinking.saturating_sub(baseline.usage.thinking),
            },
            tool_calls: self.tool_calls.saturating_sub(baseline.tool_calls),
            tool_errors: self.tool_errors.saturating_sub(baseline.tool_errors),
            model_ms: (!self.timing_history_unknown && !baseline.timing_history_unknown).then(
                || {
                    self.timings
                        .phase_model_ms
                        .saturating_sub(baseline.timings.phase_model_ms)
                },
            ),
            tools_ms: (!self.timing_history_unknown && !baseline.timing_history_unknown).then(
                || {
                    self.timings
                        .phase_tools_ms
                        .saturating_sub(baseline.timings.phase_tools_ms)
                },
            ),
            cost,
        }
    }

    /// Restore one child's non-monetary additive metrics. Monetary fields are deliberately ignored:
    /// callers must use [`Self::merge_verified_workflow_metrics`] after authenticating every signed
    /// projection through a trusted pricing port.
    pub fn merge_workflow_metrics(&mut self, child: &WorkflowMetrics) {
        self.mark_timing_unknown_after_replay();
        self.provider_attempts = self
            .provider_attempts
            .saturating_add(child.provider_attempts);
        self.turns = self.turns.saturating_add(child.completed_turns);
        self.usage.add(&child.usage);
        self.child_usage.add(&child.usage);
        self.tool_calls = self.tool_calls.saturating_add(child.tool_calls);
        self.tool_errors = self.tool_errors.saturating_add(child.tool_errors);
        // These legacy workflow duration fields cover only child model/tools time and cannot make
        // the parent run's missing context/verify history complete. Replay callers mark the
        // ledger unknown and intentionally restore only reproducible counters here.
    }

    /// Merge child monetary attribution only after the replay caller authenticated all projection
    /// HMACs. This method independently checks aggregate amount, usage, digest set, and cardinality.
    pub(crate) fn merge_verified_workflow_metrics(
        &mut self,
        child: &WorkflowMetrics,
    ) -> Result<(), &'static str> {
        let cost = child
            .cost
            .as_ref()
            .ok_or("missing workflow cost evidence")?;
        let expected_projections = usize::try_from(child.completed_turns)
            .map_err(|_| "workflow projection cardinality overflow")?;
        if expected_projections == 0
            || cost.projections.len() != expected_projections
            || cost.projections.len() > MAX_WORKFLOW_COST_PROJECTIONS
        {
            return Err("workflow projection cardinality mismatch");
        }
        let mut usage = Usage::default();
        let mut amount = Some(0u64);
        let mut digests = BTreeSet::new();
        for projection in &cost.projections {
            pricing::validate_projection_digest(projection)
                .map_err(|_| "invalid workflow projection digest")?;
            usage.add(&projection.usage);
            amount = amount.and_then(|current| current.checked_add(projection.amount_microusd));
            digests.insert(projection.rate_card_digest.clone());
        }
        if amount.is_none() {
            self.merge_workflow_metrics(child);
            self.priced_turns = self.priced_turns.saturating_add(child.completed_turns);
            self.amount_overflowed = true;
            self.rate_card_digests.extend(digests);
            self.cost_projections
                .extend(cost.projections.iter().cloned());
            return Ok(());
        }
        if usage != child.usage
            || amount != Some(cost.amount_microusd)
            || combined_rate_card_digest(&digests) != cost.rate_card_digest
        {
            return Err("workflow pricing aggregate mismatch");
        }
        self.merge_workflow_metrics(child);
        self.priced_turns = self.priced_turns.saturating_add(child.completed_turns);
        if let Some(amount) = self.amount_microusd.checked_add(cost.amount_microusd) {
            self.amount_microusd = amount;
        } else {
            self.amount_overflowed = true;
        }
        self.rate_card_digests.extend(digests);
        self.cost_projections
            .extend(cost.projections.iter().cloned());
        Ok(())
    }

    fn workflow_cost_evidence(&self) -> Option<WorkflowCostEvidence> {
        (self.turns > 0
            && self.priced_turns == self.turns
            && !self.amount_overflowed
            && self.unresolved_child_attributions == 0)
            .then(|| WorkflowCostEvidence {
                amount_microusd: self.amount_microusd,
                rate_card_digest: combined_rate_card_digest(&self.rate_card_digests),
                projections: self.cost_projections.clone(),
            })
    }

    /// Record one tool execution. `overlapped_ms` is the portion that ran concurrently with
    /// decoding (the flagship's measured payoff; 0 for effecting tools run after the turn).
    pub fn tool(&mut self, latency_ms: u64, overlapped_ms: u64, is_error: bool) {
        self.tool_calls = self.tool_calls.saturating_add(1);
        self.timings.tool_wall_ms = self.timings.tool_wall_ms.saturating_add(latency_ms);
        self.timings.tool_overlapped_ms = self
            .timings
            .tool_overlapped_ms
            .saturating_add(overlapped_ms);
        if is_error {
            self.tool_errors = self.tool_errors.saturating_add(1);
        }
    }

    /// Restore only the durable portion of a completed tool event.
    pub(crate) fn replay_tool(&mut self, is_error: bool) {
        self.tool_calls = self.tool_calls.saturating_add(1);
        if is_error {
            self.tool_errors = self.tool_errors.saturating_add(1);
        }
    }

    /// Record deterministic overflow from the early-dispatch concurrency governor to the inline
    /// fallback. `usize` is accepted at the collection boundary and converted without wrapping.
    pub fn tool_inline_overflow(&mut self, count: usize) {
        self.tool_inline_overflow_events = self
            .tool_inline_overflow_events
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
    }

    /// Cache-hit ratio for the last direct provider turn, not a cumulative or child-blended ratio.
    pub fn last_turn_cache_hit_ratio(&self) -> Option<f64> {
        self.last_turn_usage.as_ref().map(Usage::cache_hit_ratio)
    }

    /// Cache-hit ratio across direct turns on this agent's own transcript.
    pub fn local_cache_hit_ratio(&self) -> f64 {
        self.local_usage.cache_hit_ratio()
    }

    /// Aggregate ratio used only for whole-run accounting summaries.
    pub fn aggregate_cache_hit_ratio(&self) -> f64 {
        self.usage.cache_hit_ratio()
    }

    /// Monetary truth derived only from evidence that survives replay. Successful turns are still
    /// unknown until per-attempt route/rate-card snapshots exist; failed or in-flight attempts are
    /// stronger unknowns because even billable usage may be absent.
    pub fn cost_state(&self) -> CostState {
        if self.amount_overflowed {
            CostState::Unknown {
                reason: CostUnknownReason::AmountOverflow,
            }
        } else if self.unresolved_child_attributions > 0 || self.provider_attempts != self.turns {
            CostState::Unknown {
                reason: CostUnknownReason::BillingEvidenceMissing,
            }
        } else if self.legacy_unattributed {
            CostState::Unknown {
                reason: CostUnknownReason::LegacyUnattributed,
            }
        } else if self.turns > self.priced_turns {
            CostState::Unknown {
                reason: CostUnknownReason::NoVerifiedRateCard,
            }
        } else if self.turns > 0 {
            CostState::Known {
                amount_microusd: self.amount_microusd,
                rate_card_digest: combined_rate_card_digest(&self.rate_card_digests),
            }
        } else {
            CostState::Zero
        }
    }

    /// A one-screen human summary. The phase oracle made legible.
    pub fn summary(&self) -> String {
        let hit = self.usage.cache_hit_ratio() * 100.0;
        let stable = format!(
            "turns={} | tokens in={} out={} cache_read={} cache_write={} (cache hit {:.0}%) | \
             cost={} | tools={} err={} inline_overflow={}",
            self.turns,
            self.usage.input,
            self.usage.output,
            self.usage.cache_read,
            self.usage.cache_creation,
            hit,
            self.cost_state().human(),
            self.tool_calls,
            self.tool_errors,
            self.tool_inline_overflow_events,
        );
        match self.timings() {
            TimingSnapshot::Complete(timings) => {
                let overlap_pct = if timings.tool_wall_ms > 0 {
                    timings.tool_overlapped_ms as f64 / timings.tool_wall_ms as f64 * 100.0
                } else {
                    0.0
                };
                format!(
                    "{stable} | tool_wall={}ms overlapped={overlap_pct:.0}% | phase_ms context={} model={} tools={} verify={}",
                    timings.tool_wall_ms,
                    timings.phase_context_ms,
                    timings.phase_model_ms,
                    timings.phase_tools_ms,
                    timings.phase_verify_ms,
                )
            }
            TimingSnapshot::UnknownAfterReplay { observed_partial } => format!(
                "{stable} | timing=unknown_after_replay (observed_partial tool_wall={}ms context={}ms model={}ms tools={}ms verify={}ms)",
                observed_partial.tool_wall_ms,
                observed_partial.phase_context_ms,
                observed_partial.phase_model_ms,
                observed_partial.phase_tools_ms,
                observed_partial.phase_verify_ms,
            ),
        }
    }
}

fn combined_rate_card_digest(digests: &BTreeSet<String>) -> String {
    if let Some(only) = digests.iter().next().filter(|_| digests.len() == 1) {
        return only.clone();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"core/rate-card-set/v1");
    for digest in digests {
        hasher.update((digest.len() as u64).to_be_bytes());
        hasher.update(digest.as_bytes());
    }
    let bytes = hasher.finalize();
    let mut output = String::from("sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_attempts_never_invent_a_dollar_amount() {
        let mut l = Ledger::new();
        assert_eq!(l.cost_state(), CostState::Zero);
        l.attempt();
        assert_eq!(
            l.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::BillingEvidenceMissing
            }
        );
        l.turn(
            &Usage {
                input: 1000,
                output: 500,
                cache_read: 4000,
                cache_creation: 0,
                thinking: 0,
            },
            100,
        );
        assert_eq!(
            l.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::NoVerifiedRateCard
            }
        );
    }

    #[test]
    fn successful_turn_without_usage_remains_unknown_instead_of_zero() {
        let mut ledger = Ledger::new();
        ledger.attempt();
        ledger.turn_without_usage(37);

        assert_eq!(ledger.provider_attempts, 1);
        assert_eq!(ledger.turns, 0);
        assert_eq!(ledger.usage, Usage::default());
        assert_eq!(ledger.last_turn_usage, None);
        assert_eq!(
            ledger
                .timings()
                .complete()
                .expect("live timing is complete")
                .phase_model_ms,
            37
        );
        assert_eq!(
            ledger.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::BillingEvidenceMissing,
            }
        );
    }

    #[test]
    fn unresolved_attempt_and_unpriced_child_are_absorbing() {
        let mut parent = Ledger::new();
        parent.attempt();
        parent.turn(&Usage::default(), 1);
        let mut child = Ledger::new();
        child.attempt();
        parent.merge(&child);
        assert_eq!(
            parent.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::BillingEvidenceMissing
            }
        );
    }

    #[test]
    fn every_cost_unknown_reason_has_a_pinned_precedence() {
        assert_eq!(CostUnknownReason::AmountOverflow.precedence(), 0);
        assert_eq!(CostUnknownReason::BillingEvidenceMissing.precedence(), 1);
        assert_eq!(CostUnknownReason::LegacyUnattributed.precedence(), 2);
        assert_eq!(CostUnknownReason::NoVerifiedRateCard.precedence(), 3);

        let mut ledger = Ledger::new();
        ledger.attempt();
        ledger.turn(&Usage::default(), 0);
        assert_eq!(
            ledger.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::NoVerifiedRateCard
            }
        );

        ledger.mark_legacy_unattributed();
        assert_eq!(
            ledger.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::LegacyUnattributed
            }
        );

        ledger.attempt();
        assert_eq!(
            ledger.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::BillingEvidenceMissing
            }
        );

        ledger.amount_overflowed = true;
        assert_eq!(
            ledger.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::AmountOverflow
            }
        );
    }

    #[test]
    fn last_turn_and_local_cache_health_are_not_overwritten_by_child_merge() {
        let first = Usage {
            input: 100,
            cache_read: 0,
            ..Usage::default()
        };
        let second = Usage {
            input: 0,
            cache_read: 100,
            ..Usage::default()
        };
        let child_usage = Usage {
            input: 900,
            cache_read: 100,
            ..Usage::default()
        };
        let mut parent = Ledger::new();
        parent.attempt();
        parent.attempt();
        parent.turn(&first, 1);
        parent.turn(&second, 1);
        let mut child = Ledger::new();
        child.attempt();
        child.turn(&child_usage, 1);
        parent.merge(&child);

        assert_eq!(parent.provider_attempts, 3);
        assert_eq!(parent.last_turn_usage, Some(second));
        assert_eq!(parent.last_turn_cache_hit_ratio(), Some(1.0));
        assert_eq!(parent.local_cache_hit_ratio(), 0.5);
        assert_eq!(parent.child_usage, child_usage);
        assert!(parent.aggregate_cache_hit_ratio() < parent.local_cache_hit_ratio());
    }

    #[test]
    fn inline_overflow_counter_is_saturating_visible_and_additive() {
        let mut parent = Ledger::new();
        parent.tool_inline_overflow(2);
        let mut child = Ledger::new();
        child.tool_inline_overflow(3);
        parent.merge(&child);

        assert_eq!(parent.tool_inline_overflow_events, 5);
        assert!(parent.summary().contains("inline_overflow=5"));
        parent.tool_inline_overflow_events = u64::MAX;
        parent.tool_inline_overflow(1);
        assert_eq!(parent.tool_inline_overflow_events, u64::MAX);
    }

    #[test]
    fn unsigned_workflow_cost_evidence_never_constructs_known() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let metrics = WorkflowMetrics {
            provider_attempts: 1,
            completed_turns: 1,
            usage: Usage {
                input: 3,
                output: 2,
                ..Usage::default()
            },
            cost: Some(WorkflowCostEvidence {
                amount_microusd: 7,
                rate_card_digest: digest.clone(),
                projections: Vec::new(),
            }),
            ..WorkflowMetrics::default()
        };
        let mut restored = Ledger::new();
        restored.merge_workflow_metrics(&metrics);
        assert_eq!(
            restored.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::NoVerifiedRateCard,
            }
        );
    }

    fn fixture_projection(tag: &str, key: [u8; 32], usage: Usage) -> CostProjection {
        let card = core_protocol::RateCard {
            version: core_protocol::PricingVersion::V1,
            route: core_protocol::PricingRoute {
                provider_id: format!("provider-{tag}"),
                model_id: format!("model-{tag}"),
                catalog_digest: format!("sha256:{}", tag.repeat(64)),
                capability_digest: format!("sha256:{}", "f".repeat(64)),
            },
            provenance: format!("manifest@{tag}"),
            issued_at_unix_secs: 1,
            expires_at_unix_secs: 100,
            rates: core_protocol::TokenRateCard {
                input_microusd_per_million: 1_000_000,
                output_microusd_per_million: 1_000_000,
                cache_creation_microusd_per_million: 1_000_000,
                cache_read_microusd_per_million: 1_000_000,
                thinking_microusd_per_million: 1_000_000,
            },
        };
        let signed = pricing::sign_rate_card(card, format!("root-{tag}"), key).unwrap();
        let authority = pricing::HmacPricingAuthority::new(vec![(
            signed.clone(),
            pricing::HmacPricingKey::from_bytes(key),
        )])
        .unwrap();
        authority
            .project(
                &signed,
                CostProjectionIdentity {
                    tenant_id: "tenant".into(),
                    run_id: format!("run-{tag}"),
                    turn_id: 0,
                    provider_attempt: 1,
                    attribution: None,
                },
                usage,
                50,
            )
            .unwrap()
    }

    #[test]
    fn workflow_delta_digest_excludes_prior_rate_card_history() {
        let first_usage = Usage {
            input: 1,
            output: 1,
            ..Usage::default()
        };
        let second_usage = Usage {
            input: 2,
            output: 1,
            ..Usage::default()
        };
        let first = fixture_projection("a", [1; 32], first_usage);
        let second = fixture_projection("b", [2; 32], second_usage);
        let mut ledger = Ledger::new();
        ledger.attempt();
        ledger.turn(&first_usage, 1);
        ledger.apply_cost_projection(&first).unwrap();
        let baseline = ledger.clone();

        ledger.attempt();
        ledger.turn(&second_usage, 1);
        ledger.apply_cost_projection(&second).unwrap();
        let delta = ledger.workflow_metrics_since(&baseline);
        let cost = delta.cost.expect("the new turn is fully priced");
        assert_eq!(cost.rate_card_digest, second.rate_card_digest);
        assert_eq!(cost.projections, vec![second]);
    }
}
