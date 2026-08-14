//! Production ownership and durable append helpers for frozen-slot evidence.

use super::*;
use iteron_protocol::{
    PolicyActionId, PolicyActionV1, PolicyDecisionDisposition, PolicyHarnessErrorCode,
    PolicyHarnessOutcomeId, PolicyTerminalOutcome, PolicyVerifierOutcome, Usage, slot::SlotId,
};
use serde::Serialize;

pub(super) const CONTEXT_SLOT: &str = "core/context";
pub(super) const TOOL_POLICY_SLOT: &str = "core/tool_policy";
pub(super) const MEMORY_SLOT: &str = "core/memory";
#[cfg(test)]
pub(super) const ROUTER_SLOT: &str = "core/router";
#[cfg(test)]
pub(super) const PLANNER_SLOT: &str = "core/planner";
pub(super) const COLLABORATION_SLOT: &str = "core/collaboration";
pub(super) const SCHEDULER_SLOT: &str = "core/scheduler";
pub(super) const VERIFIER_SLOT: &str = "core/verifier";
pub(super) const MODEL_ROUTER_SLOT: &str = "core/model_router";

/// Propensity recorded for the action a deterministic slot selected: the built-in strategies do not
/// sample, so the selected action was taken with probability one (1e6 parts per million).
const DETERMINISTIC_PROPENSITY_PPM: u32 = 1_000_000;

pub(super) struct PolicyTurnCounterBaseline {
    usage: Usage,
    provider_attempts: u32,
    completed_turns: u32,
}

impl PolicyTurnCounterBaseline {
    fn capture(ledger: &Ledger) -> Self {
        let counters = ledger.reproducible_counters();
        Self {
            usage: counters.usage,
            provider_attempts: counters.provider_attempts,
            completed_turns: counters.completed_turns,
        }
    }
}

pub(super) struct PolicyDecisionDraft {
    eligible_actions: Vec<PolicyActionId>,
    selected_action: Option<PolicyActionId>,
    disposition: PolicyDecisionDisposition,
    selected_score_micros: Option<i64>,
    propensity_ppm: Option<u32>,
    feature_schema_id: String,
    feature_digest_sha256: String,
    fixed_invariants_digest_sha256: String,
}

impl PolicyDecisionDraft {
    pub(super) fn selected<F: Serialize, I: Serialize>(
        slot: &'static str,
        eligible: &[PolicyActionV1],
        selected: PolicyActionV1,
        feature_schema_id: &str,
        features: &F,
        fixed_invariants: &I,
    ) -> Result<Self, KernelError> {
        Self::new(
            slot,
            eligible,
            Some(selected),
            PolicyDecisionDisposition::Selected,
            feature_schema_id,
            features,
            fixed_invariants,
        )
    }

    pub(super) fn baseline_fallback<F: Serialize, I: Serialize>(
        slot: &'static str,
        eligible: &[PolicyActionV1],
        feature_schema_id: &str,
        features: &F,
        fixed_invariants: &I,
    ) -> Result<Self, KernelError> {
        Self::new(
            slot,
            eligible,
            None,
            PolicyDecisionDisposition::BaselineFallback,
            feature_schema_id,
            features,
            fixed_invariants,
        )
    }

    pub(super) fn abstained<F: Serialize, I: Serialize>(
        slot: &'static str,
        eligible: &[PolicyActionV1],
        feature_schema_id: &str,
        features: &F,
        fixed_invariants: &I,
    ) -> Result<Self, KernelError> {
        Self::new(
            slot,
            eligible,
            None,
            PolicyDecisionDisposition::Abstained,
            feature_schema_id,
            features,
            fixed_invariants,
        )
    }

    fn new<F: Serialize, I: Serialize>(
        slot: &'static str,
        eligible: &[PolicyActionV1],
        selected: Option<PolicyActionV1>,
        disposition: PolicyDecisionDisposition,
        feature_schema_id: &str,
        features: &F,
        fixed_invariants: &I,
    ) -> Result<Self, KernelError> {
        let slot = SlotId(slot.to_owned());
        Ok(Self {
            eligible_actions: eligible
                .iter()
                .copied()
                .map(|action| PolicyActionId::for_slot(&slot, action))
                .collect::<Result<_, _>>()
                .map_err(|error| KernelError::PolicyEvidence(error.to_string()))?,
            selected_action: selected
                .map(|action| PolicyActionId::for_slot(&slot, action))
                .transpose()
                .map_err(|error| KernelError::PolicyEvidence(error.to_string()))?,
            disposition,
            selected_score_micros: None,
            propensity_ppm: (disposition == PolicyDecisionDisposition::Selected).then_some(
                iteron_tunables::param_integer(
                    "cli.runtime.policy_evidence.deterministic_propensity_ppm",
                    DETERMINISTIC_PROPENSITY_PPM,
                ),
            ),
            feature_schema_id: feature_schema_id.to_owned(),
            feature_digest_sha256: digest_json("iteron:policy-features:v1", features)?,
            fixed_invariants_digest_sha256: digest_json(
                "iteron:policy-fixed-invariants:v1",
                fixed_invariants,
            )?,
        })
    }

    fn into_input(self) -> policy_evidence_recorder::PolicyDecisionInput {
        policy_evidence_recorder::PolicyDecisionInput {
            eligible_actions: self.eligible_actions,
            selected_action: self.selected_action,
            disposition: self.disposition,
            selected_score_micros: self.selected_score_micros,
            propensity_ppm: self.propensity_ppm,
            feature_schema_id: self.feature_schema_id,
            feature_digest_sha256: self.feature_digest_sha256,
            fixed_invariants_digest_sha256: self.fixed_invariants_digest_sha256,
        }
    }
}

impl Agent {
    /// Restore once from the verified physical journal while this Agent owns its writer.
    /// Legacy test agents without a tunables pin deliberately emit no evidence.
    pub(super) fn ensure_policy_evidence(&mut self) -> Result<bool, KernelError> {
        if self.policy_evidence.is_some() {
            return Ok(true);
        }
        let Some(pin) = self.tunables_pin.as_ref() else {
            return Ok(false);
        };
        let events = iteron_record::replay_timed(self.rollout.path())?;
        let recorder = policy_evidence_recorder::PolicyEvidenceRecorder::restore_or_begin(
            self.rollout.run_id(),
            pin.resolution_digest_sha256().to_owned(),
            self.policy_runtime_bindings().to_vec(),
            &events,
        )
        .map_err(|error| self.policy_evidence_error(error))?;
        self.policy_evidence = Some(recorder);
        Ok(true)
    }

    pub(super) fn begin_policy_decision(
        &mut self,
        slot: &'static str,
        turn: Option<TurnId>,
    ) -> Result<Option<policy_evidence_recorder::PolicyOpportunity>, KernelError> {
        if !self.ensure_policy_evidence()? {
            return Ok(None);
        }
        self.policy_evidence
            .as_mut()
            .expect("ensured above")
            .begin_opportunity(&SlotId(slot.to_owned()), turn)
            .map(Some)
            .map_err(|error| self.policy_evidence_error(error))
    }

    pub(super) fn append_policy_decision(
        &mut self,
        opportunity: Option<policy_evidence_recorder::PolicyOpportunity>,
        draft: PolicyDecisionDraft,
    ) -> Result<(), KernelError> {
        let Some(opportunity) = opportunity else {
            return Ok(());
        };
        let mut recorder = self
            .policy_evidence
            .take()
            .ok_or_else(|| KernelError::PolicyEvidence("recorder ownership was lost".into()))?;
        let started = Instant::now();
        let result = recorder.append_decision(&mut self.rollout, &opportunity, draft.into_input());
        self.ledger.record_fsync_latency_us(elapsed_us(started));
        self.policy_evidence = Some(recorder);
        result
            .map(|_| ())
            .map_err(|error| self.policy_evidence_error(error))
    }

    pub(super) fn record_completed_policy_decision(
        &mut self,
        slot: &'static str,
        turn: Option<TurnId>,
        draft: PolicyDecisionDraft,
    ) -> Result<(), KernelError> {
        let opportunity = self.begin_policy_decision(slot, turn)?;
        #[cfg(test)]
        if slot == TOOL_POLICY_SLOT
            && self.fail_next_durable_append == Some(DurableAppendFault::ToolPolicyDecision)
        {
            self.fail_next_durable_append = None;
            return Err(self.policy_evidence_error(
                iteron_record::RecordError::Io(std::io::Error::other(
                    "injected policy-decision sync failure",
                ))
                .into(),
            ));
        }
        self.append_policy_decision(opportunity, draft)
    }

    pub(super) fn observe_policy_turn_start(&mut self, turn: TurnId, started_at_us: u64) {
        if let Some(recorder) = self.policy_evidence.as_mut() {
            recorder.observe_turn_start(turn, started_at_us);
            self.policy_turn_cost_baseline = Some(self.ledger.cost_state());
            self.policy_turn_counter_baseline =
                Some(PolicyTurnCounterBaseline::capture(&self.ledger));
        }
    }

    pub(super) fn append_policy_turn_outcome(
        &mut self,
        turn: TurnId,
        terminal: PolicyTerminalOutcome,
        verifier: PolicyVerifierOutcome,
        harness_error_code: Option<PolicyHarnessErrorCode>,
    ) -> Result<(), KernelError> {
        if !self.ensure_policy_evidence()? {
            return Ok(());
        }
        if self
            .policy_evidence
            .as_ref()
            .is_some_and(|recorder| recorder.is_turn_terminal(turn))
        {
            self.policy_turn_cost_baseline = None;
            self.policy_turn_counter_baseline = None;
            return Ok(());
        }
        let now_us = self.rollout.segment_elapsed_us();
        let current_cost = self.ledger.cost_state();
        let cost_microusd =
            policy_cost_delta_microusd(self.policy_turn_cost_baseline.as_ref(), &current_cost);
        let (input_tokens, output_tokens) = policy_turn_tokens(
            self.policy_turn_counter_baseline.as_ref(),
            &self.ledger.reproducible_counters(),
        );
        let (join, latency_us) = {
            let recorder = self.policy_evidence.as_ref().expect("ensured above");
            (
                recorder.turn_join(turn),
                recorder.turn_latency_us(turn, now_us),
            )
        };
        let input = policy_evidence_recorder::PolicyOutcomeInput {
            terminal,
            quality_micros: policy_quality_micros(terminal, verifier),
            cost_microusd,
            input_tokens,
            output_tokens,
            latency_us,
            verifier,
            harness_error_code: harness_error_code.map(PolicyHarnessOutcomeId::single),
        };
        let mut recorder = self.policy_evidence.take().expect("ensured above");
        let started = Instant::now();
        let result = recorder.append_turn_outcome(&mut self.rollout, turn, &join, input);
        self.ledger.record_fsync_latency_us(elapsed_us(started));
        self.policy_evidence = Some(recorder);
        let result = result
            .map(|_| ())
            .map_err(|error| self.policy_evidence_error(error));
        if result.is_ok() {
            self.policy_turn_cost_baseline = None;
            self.policy_turn_counter_baseline = None;
        }
        result
    }

    /// Close the session actor's policy-run segment exactly once. A later process resume validates
    /// this terminal segment and begins a new deterministic policy run rather than appending
    /// decisions after a terminal outcome.
    pub(crate) fn finalize_policy_run(&mut self) -> Result<(), KernelError> {
        if !self.ensure_policy_evidence()? {
            return Ok(());
        }
        if self
            .policy_evidence
            .as_ref()
            .is_some_and(policy_evidence_recorder::PolicyEvidenceRecorder::is_run_terminal)
        {
            return Ok(());
        }
        let join = self
            .policy_evidence
            .as_ref()
            .expect("ensured above")
            .run_join();
        let mut recorder = self.policy_evidence.take().expect("ensured above");
        let started = Instant::now();
        let result = recorder.append_run_outcome(&mut self.rollout, TurnId(self.seq_turn), &join);
        self.ledger.record_fsync_latency_us(elapsed_us(started));
        self.policy_evidence = Some(recorder);
        result
            .map(|_| ())
            .map_err(|error| self.policy_evidence_error(error))
    }

    fn policy_evidence_error(
        &mut self,
        error: policy_evidence_recorder::PolicyEvidenceRecorderError,
    ) -> KernelError {
        match error.into_record_error() {
            Ok(error) => {
                self.record_failed = true;
                self.diagnostic_record_append_failed();
                KernelError::Record(error)
            }
            Err(error) => KernelError::PolicyEvidence(error.to_string()),
        }
    }
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<String, KernelError> {
    let encoded = serde_json::to_vec(value).map_err(|_| {
        KernelError::PolicyEvidence("policy observation was not serializable".into())
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn policy_harness_error_code(error: &KernelError) -> PolicyHarnessErrorCode {
    match error {
        KernelError::Provider(_) => PolicyHarnessErrorCode::ProviderError,
        KernelError::Record(_) => PolicyHarnessErrorCode::RecordError,
        KernelError::InvalidRouteMetadata { .. } | KernelError::InvalidRoute(_) => {
            PolicyHarnessErrorCode::RouteError
        }
        KernelError::ProviderRunNoticeLimit => PolicyHarnessErrorCode::ProviderNoticeLimit,
        KernelError::InvalidBudget(_) => PolicyHarnessErrorCode::BudgetError,
        KernelError::InferenceBudgetExhausted(reason) => policy_budget_harness_error_code(reason),
        KernelError::InvalidSubmission(_) => PolicyHarnessErrorCode::SubmissionError,
        KernelError::UnpricedUsdCeiling
        | KernelError::Pricing(_)
        | KernelError::PricingLedger(_) => PolicyHarnessErrorCode::PricingError,
        KernelError::InvalidPermissionPolicy(_) => PolicyHarnessErrorCode::PermissionError,
        KernelError::RuntimePolicyAlreadyRecorded => PolicyHarnessErrorCode::RuntimePolicyError,
        KernelError::UnknownEffects { .. } | KernelError::EffectJournal(_) => {
            PolicyHarnessErrorCode::EffectUnknown
        }
        KernelError::EffectBoundary(_) => PolicyHarnessErrorCode::EffectError,
        KernelError::IdentityExhausted(_) => PolicyHarnessErrorCode::IdentityExhausted,
        KernelError::OpaqueProviderRetries => PolicyHarnessErrorCode::OpaqueProviderRetries,
        KernelError::ContextWindowExceeded { .. }
        | KernelError::ContextBudget(_)
        | KernelError::InstructionContextTooLarge { .. }
        | KernelError::InstructionContextAlreadyResolved
        | KernelError::EnvironmentContextTooLarge { .. }
        | KernelError::EnvironmentContextAlreadyResolved
        | KernelError::ContextResolution(_)
        | KernelError::ContextAlreadyResolved => PolicyHarnessErrorCode::ContextError,
        KernelError::AgentCatalogAlreadyResolved => PolicyHarnessErrorCode::AgentCatalogError,
        KernelError::TunablesAlreadyResolved | KernelError::TunablesNotResolved => {
            PolicyHarnessErrorCode::TunablesError
        }
        KernelError::ToolingPolicy(_) => PolicyHarnessErrorCode::ToolingPolicyError,
        KernelError::ExecutionPolicy(_) => PolicyHarnessErrorCode::ExecutionPolicyError,
        KernelError::ToolOutputSpill(_) => PolicyHarnessErrorCode::ToolOutputSpillError,
        KernelError::McpLifecycle(_) => PolicyHarnessErrorCode::McpLifecycleError,
        KernelError::PolicyEvidence(_) => PolicyHarnessErrorCode::PolicyEvidenceError,
        KernelError::DelegationDepthExceeded => PolicyHarnessErrorCode::DelegationError,
        #[cfg(test)]
        KernelError::WorkflowEngine(_) => PolicyHarnessErrorCode::WorkflowError,
    }
}

pub(super) fn policy_budget_harness_error_code(reason: &str) -> PolicyHarnessErrorCode {
    match reason {
        "max_turns" => PolicyHarnessErrorCode::BudgetMaxTurns,
        "max_tokens" => PolicyHarnessErrorCode::BudgetMaxTokens,
        "max_usd" => PolicyHarnessErrorCode::BudgetMaxUsd,
        "max_wall_secs" => PolicyHarnessErrorCode::BudgetMaxWallSecs,
        "verify_attempts" => PolicyHarnessErrorCode::BudgetVerifyAttempts,
        _ => PolicyHarnessErrorCode::BudgetError,
    }
}

fn policy_cost_microusd(cost: &CostState) -> Option<u64> {
    match cost {
        CostState::Zero => Some(0),
        CostState::Known {
            amount_microusd, ..
        } => Some(*amount_microusd),
        CostState::Unknown { .. } => None,
    }
}

fn policy_cost_delta_microusd(baseline: Option<&CostState>, current: &CostState) -> Option<u64> {
    match (
        baseline.and_then(policy_cost_microusd),
        policy_cost_microusd(current),
    ) {
        (Some(before), Some(after)) => after.checked_sub(before),
        (None, Some(0)) => Some(0),
        _ => None,
    }
}

fn policy_turn_tokens(
    baseline: Option<&PolicyTurnCounterBaseline>,
    current: &iteron_obs::ReproducibleCounters,
) -> (Option<u64>, Option<u64>) {
    let Some(baseline) = baseline else {
        return (None, None);
    };
    let attempts = current
        .provider_attempts
        .checked_sub(baseline.provider_attempts);
    let completions = current
        .completed_turns
        .checked_sub(baseline.completed_turns);
    if attempts.is_none() || attempts != completions {
        return (None, None);
    }
    (
        current.usage.input.checked_sub(baseline.usage.input),
        current.usage.output.checked_sub(baseline.usage.output),
    )
}

const fn policy_quality_micros(
    terminal: PolicyTerminalOutcome,
    verifier: PolicyVerifierOutcome,
) -> Option<i64> {
    match (terminal, verifier) {
        (PolicyTerminalOutcome::Succeeded, PolicyVerifierOutcome::Passed) => Some(1_000_000),
        (_, PolicyVerifierOutcome::TestFailure) => Some(0),
        _ => None,
    }
}
