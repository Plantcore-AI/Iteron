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

use core_protocol::{Phase, Usage, WorkflowMetrics};
use serde::{Deserialize, Serialize};

/// Honest cumulative monetary state. Core does not infer billing from token counts without a
/// route-bound, versioned rate card and does not treat an attempt without usage as free.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CostState {
    /// No provider request has been admitted, so zero is provable.
    #[default]
    Zero,
    /// Reserved for the future per-attempt rate-card transaction. Amounts are fixed-point micro-USD,
    /// never floating point; no production path constructs this variant yet.
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
    NoVerifiedRateCard,
    BillingEvidenceMissing,
    LegacyUnattributed,
}

impl CostUnknownReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::NoVerifiedRateCard => "no_verified_rate_card",
            Self::BillingEvidenceMissing => "billing_evidence_missing",
            Self::LegacyUnattributed => "legacy_unattributed",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::NoVerifiedRateCard => "no verified rate card",
            Self::BillingEvidenceMissing => "billing evidence missing for one or more attempts",
            Self::LegacyUnattributed => "legacy usage has no route/rate-card attribution",
        }
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
    /// tau_wall: total measured tool wall-clock, and how much of it overlapped decoding.
    pub tool_wall_ms: u64,
    pub tool_overlapped_ms: u64,
    pub tool_calls: u64,
    pub tool_errors: u64,
    pub phase_model_ms: u64,
    pub phase_tools_ms: u64,
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

    /// Record a completed model turn's usage by cache class.
    pub fn turn(&mut self, usage: &Usage, model_ms: u64) {
        self.turns += 1;
        self.usage.add(usage);
        self.local_usage.add(usage);
        self.last_turn_usage = Some(*usage);
        self.phase_model_ms += model_ms;
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
        self.tool_wall_ms = self.tool_wall_ms.saturating_add(child.tool_wall_ms);
        self.tool_overlapped_ms = self
            .tool_overlapped_ms
            .saturating_add(child.tool_overlapped_ms);
        self.tool_calls = self.tool_calls.saturating_add(child.tool_calls);
        self.tool_errors = self.tool_errors.saturating_add(child.tool_errors);
        self.phase_model_ms = self.phase_model_ms.saturating_add(child.phase_model_ms);
        self.phase_tools_ms = self.phase_tools_ms.saturating_add(child.phase_tools_ms);
    }

    /// Content-free attribution snapshot suitable for the parent workflow journal. Child rollouts
    /// keep full messages; the parent needs only additive accounting to make resume and session
    /// projection preserve the same hard ceilings as the live run.
    pub fn workflow_metrics(&self) -> WorkflowMetrics {
        WorkflowMetrics {
            provider_attempts: self.provider_attempts,
            completed_turns: self.turns,
            usage: self.usage,
            tool_calls: self.tool_calls,
            tool_errors: self.tool_errors,
            model_ms: self.phase_model_ms,
            tools_ms: self.phase_tools_ms,
        }
    }

    /// Metrics attributable to work after `baseline`. Workflow terminal cards use this delta so a
    /// follow-up does not relabel the whole session's historical usage as the latest workflow.
    pub fn workflow_metrics_since(&self, baseline: &Ledger) -> WorkflowMetrics {
        WorkflowMetrics {
            provider_attempts: self
                .provider_attempts
                .saturating_sub(baseline.provider_attempts),
            completed_turns: self.turns.saturating_sub(baseline.turns),
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
            model_ms: self.phase_model_ms.saturating_sub(baseline.phase_model_ms),
            tools_ms: self.phase_tools_ms.saturating_sub(baseline.phase_tools_ms),
        }
    }

    /// Restore one child's additive metrics from a verified parent workflow terminal. This mirrors
    /// [`Self::merge`] without pretending the child was a direct request on the active transcript.
    pub fn merge_workflow_metrics(&mut self, child: &WorkflowMetrics) {
        self.provider_attempts = self
            .provider_attempts
            .saturating_add(child.provider_attempts);
        self.turns = self.turns.saturating_add(child.completed_turns);
        self.usage.add(&child.usage);
        self.child_usage.add(&child.usage);
        self.tool_calls = self.tool_calls.saturating_add(child.tool_calls);
        self.tool_errors = self.tool_errors.saturating_add(child.tool_errors);
        self.phase_model_ms = self.phase_model_ms.saturating_add(child.model_ms);
        self.phase_tools_ms = self.phase_tools_ms.saturating_add(child.tools_ms);
    }

    /// Record one tool execution. `overlapped_ms` is the portion that ran concurrently with
    /// decoding (the flagship's measured payoff; 0 for effecting tools run after the turn).
    pub fn tool(&mut self, latency_ms: u64, overlapped_ms: u64, is_error: bool) {
        self.tool_calls += 1;
        self.tool_wall_ms += latency_ms;
        self.tool_overlapped_ms += overlapped_ms;
        if is_error {
            self.tool_errors += 1;
        }
    }

    pub fn phase_tools(&mut self, ms: u64) {
        self.phase_tools_ms += ms;
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
        if self.provider_attempts > self.turns {
            CostState::Unknown {
                reason: CostUnknownReason::BillingEvidenceMissing,
            }
        } else if self.turns > 0 {
            CostState::Unknown {
                reason: CostUnknownReason::NoVerifiedRateCard,
            }
        } else {
            CostState::Zero
        }
    }

    /// A one-screen human summary. The phase oracle made legible.
    pub fn summary(&self) -> String {
        let hit = self.usage.cache_hit_ratio() * 100.0;
        let overlap_pct = if self.tool_wall_ms > 0 {
            self.tool_overlapped_ms as f64 / self.tool_wall_ms as f64 * 100.0
        } else {
            0.0
        };
        format!(
            "turns={} | tokens in={} out={} cache_read={} cache_write={} (cache hit {:.0}%) | \
             cost={} | tools={} err={} | tool_wall={}ms overlapped={:.0}% | model_ms={}",
            self.turns,
            self.usage.input,
            self.usage.output,
            self.usage.cache_read,
            self.usage.cache_creation,
            hit,
            self.cost_state().human(),
            self.tool_calls,
            self.tool_errors,
            self.tool_wall_ms,
            overlap_pct,
            self.phase_model_ms,
        )
    }
}

/// A phase span: name a phase, measure its wall-clock. The harness declaring its own phase
/// is the whole point.
pub struct PhaseSpan {
    pub phase: Phase,
    started: std::time::Instant,
}

impl PhaseSpan {
    pub fn enter(phase: Phase) -> Self {
        PhaseSpan {
            phase,
            started: std::time::Instant::now(),
        }
    }
    pub fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
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
}
