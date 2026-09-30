//! Single turn-cost/counter/verifier evidence owner and physical terminal-record adapter.
//! Typed disjoint journal/ledger/recorder ports retain their original owners; no Agent is borrowed.
use super::policy_evidence::policy_budget_harness_error_code;
use super::policy_evidence_recorder::{
    PolicyEvidenceRecorder, PolicyEvidenceRecorderError, PolicyOutcomeInput,
};
use iteron_obs::{CostState, Ledger, ReproducibleCounters};
use iteron_protocol::{
    Event, EventKind, Outcome, Phase, PolicyHarnessErrorCode, PolicyHarnessOutcomeId,
    PolicyTerminalOutcome, PolicyVerifierOutcome, Seq, TurnId,
};
use iteron_record::{RecordError, Rollout};
use std::time::Instant;

pub(super) struct TerminalRecordOwner {
    cost_baseline: Option<CostState>,
    counters_baseline: Option<ReproducibleCounters>,
    verifier: PolicyVerifierOutcome,
}

impl Default for TerminalRecordOwner {
    fn default() -> Self {
        Self {
            cost_baseline: None,
            counters_baseline: None,
            verifier: PolicyVerifierOutcome::NotRun,
        }
    }
}

impl TerminalRecordOwner {
    pub(super) fn observe_start(
        &mut self,
        recorder: &mut PolicyEvidenceRecorder,
        turn: TurnId,
        started_at_us: u64,
        ledger: &Ledger,
    ) {
        recorder.observe_turn_start(turn, started_at_us);
        self.cost_baseline = Some(ledger.cost_state());
        self.counters_baseline = Some(ledger.reproducible_counters());
    }
    pub(super) fn observe_verifier(&mut self, verifier: PolicyVerifierOutcome) {
        self.verifier = verifier;
    }
    pub(super) fn verifier(&self) -> PolicyVerifierOutcome {
        self.verifier
    }
    pub(super) fn reset_verifier(&mut self) {
        self.verifier = PolicyVerifierOutcome::NotRun;
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn append_policy_outcome(
        &mut self,
        recorder: &mut PolicyEvidenceRecorder,
        rollout: &mut Rollout,
        ledger: &mut Ledger,
        turn: TurnId,
        terminal: PolicyTerminalOutcome,
        verifier: PolicyVerifierOutcome,
        harness_error_code: Option<PolicyHarnessErrorCode>,
    ) -> Result<(), PolicyEvidenceRecorderError> {
        if recorder.is_turn_terminal(turn) {
            self.clear_baselines();
            return Ok(());
        }
        let cost_microusd = cost_delta(self.cost_baseline.as_ref(), &ledger.cost_state());
        let (input_tokens, output_tokens) = turn_tokens(
            self.counters_baseline.as_ref(),
            &ledger.reproducible_counters(),
        );
        let join = recorder.turn_join(turn);
        let input = PolicyOutcomeInput {
            terminal,
            quality_micros: quality(terminal, verifier),
            cost_microusd,
            input_tokens,
            output_tokens,
            latency_us: recorder.turn_latency_us(turn, rollout.segment_elapsed_us()),
            verifier,
            harness_error_code: harness_error_code.map(PolicyHarnessOutcomeId::single),
        };
        let started = Instant::now();
        let result = recorder.append_turn_outcome(rollout, turn, &join, input);
        ledger.record_fsync_latency_us(elapsed_us(started));
        if result.is_ok() {
            self.clear_baselines();
        }
        result.map(|_| ())
    }

    /// Idle and Done share one confirmed append_batch barrier. The caller may project a terminal
    /// only after this method succeeds; an incomplete receipt is a failed record, never success.
    pub(super) fn append_visible_terminal(
        &self,
        rollout: &mut Rollout,
        ledger: &mut Ledger,
        turn: TurnId,
        outcome: String,
    ) -> Result<(), RecordError> {
        let events = [
            Event {
                seq: Seq::ZERO,
                turn,
                kind: EventKind::Phase { phase: Phase::Idle },
            },
            Event {
                seq: Seq::ZERO,
                turn,
                kind: EventKind::Done { outcome },
            },
        ];
        let started = Instant::now();
        let result = rollout.append_batch(&events);
        ledger.record_fsync_latency_us(elapsed_us(started));
        match result {
            Ok(sequences) if sequences.len() == events.len() => Ok(()),
            Ok(_) => Err(RecordError::InvalidAppendBatch {
                reason: "run terminal batch returned an incomplete sequence receipt",
            }),
            Err(error) => Err(error),
        }
    }

    pub(super) fn classify_outcome(
        &self,
        outcome: &Outcome,
        usage_unavailable: bool,
    ) -> (PolicyTerminalOutcome, Option<PolicyHarnessErrorCode>) {
        match outcome {
            Outcome::Done => (PolicyTerminalOutcome::Succeeded, None),
            Outcome::Drained => (
                PolicyTerminalOutcome::Cancelled,
                Some(PolicyHarnessErrorCode::OperatorDrain),
            ),
            Outcome::BudgetExhausted(reason) => (
                PolicyTerminalOutcome::BudgetExhausted,
                Some(policy_budget_harness_error_code(reason)),
            ),
            Outcome::Interrupted => (
                PolicyTerminalOutcome::Interrupted,
                Some(PolicyHarnessErrorCode::OperatorInterrupted),
            ),
            Outcome::Stuck => (
                PolicyTerminalOutcome::Failed,
                Some(PolicyHarnessErrorCode::ConsecutiveToolErrors),
            ),
            Outcome::HarnessError => (
                PolicyTerminalOutcome::Failed,
                Some(if usage_unavailable {
                    PolicyHarnessErrorCode::UsageUnavailable
                } else {
                    PolicyHarnessErrorCode::HarnessFailure
                }),
            ),
        }
    }
    fn clear_baselines(&mut self) {
        self.cost_baseline = None;
        self.counters_baseline = None;
    }
}

fn elapsed_us(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}
fn known_cost(cost: &CostState) -> Option<u64> {
    match cost {
        CostState::Zero => Some(0),
        CostState::Known {
            amount_microusd, ..
        } => Some(*amount_microusd),
        CostState::Unknown { .. } => None,
    }
}
fn cost_delta(baseline: Option<&CostState>, current: &CostState) -> Option<u64> {
    match (baseline.and_then(known_cost), known_cost(current)) {
        (Some(before), Some(after)) => after.checked_sub(before),
        (None, Some(0)) => Some(0),
        _ => None,
    }
}
fn turn_tokens(
    baseline: Option<&ReproducibleCounters>,
    current: &ReproducibleCounters,
) -> (Option<u64>, Option<u64>) {
    let Some(baseline) = baseline else {
        return (None, None);
    };
    let attempts = current
        .provider_attempts
        .checked_sub(baseline.provider_attempts);
    let completed = current
        .completed_turns
        .checked_sub(baseline.completed_turns);
    if attempts.is_none() || attempts != completed {
        return (None, None);
    }
    (
        current.usage.input.checked_sub(baseline.usage.input),
        current.usage.output.checked_sub(baseline.usage.output),
    )
}
const fn quality(terminal: PolicyTerminalOutcome, verifier: PolicyVerifierOutcome) -> Option<i64> {
    match (terminal, verifier) {
        (PolicyTerminalOutcome::Succeeded, PolicyVerifierOutcome::Passed) => Some(1_000_000),
        (_, PolicyVerifierOutcome::TestFailure) => Some(0),
        _ => None,
    }
}
