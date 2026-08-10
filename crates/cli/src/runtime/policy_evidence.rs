//! Production ownership and durable append helpers for frozen-slot evidence.

use super::*;
use core_protocol::{
    PolicyActionId, PolicyDecisionDisposition, PolicyTerminalOutcome, PolicyVerifierOutcome, Usage,
    slot::SlotId,
};
use serde::Serialize;

pub(super) const CONTEXT_SLOT: &str = "core/context";
pub(super) const TOOL_POLICY_SLOT: &str = "core/tool_policy";
pub(super) const MEMORY_SLOT: &str = "core/memory";
pub(super) const ROUTER_SLOT: &str = "core/router";
pub(super) const PLANNER_SLOT: &str = "core/planner";
pub(super) const COLLABORATION_SLOT: &str = "core/collaboration";
pub(super) const SCHEDULER_SLOT: &str = "core/scheduler";
pub(super) const VERIFIER_SLOT: &str = "core/verifier";
pub(super) const MODEL_ROUTER_SLOT: &str = "core/model_router";

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
        eligible: &[&str],
        selected: &str,
        feature_schema_id: &str,
        features: &F,
        fixed_invariants: &I,
    ) -> Result<Self, KernelError> {
        Self::new(
            eligible,
            Some(selected),
            PolicyDecisionDisposition::Selected,
            feature_schema_id,
            features,
            fixed_invariants,
        )
    }

    pub(super) fn baseline_fallback<F: Serialize, I: Serialize>(
        eligible: &[&str],
        feature_schema_id: &str,
        features: &F,
        fixed_invariants: &I,
    ) -> Result<Self, KernelError> {
        Self::new(
            eligible,
            None,
            PolicyDecisionDisposition::BaselineFallback,
            feature_schema_id,
            features,
            fixed_invariants,
        )
    }

    pub(super) fn abstained<F: Serialize, I: Serialize>(
        eligible: &[&str],
        feature_schema_id: &str,
        features: &F,
        fixed_invariants: &I,
    ) -> Result<Self, KernelError> {
        Self::new(
            eligible,
            None,
            PolicyDecisionDisposition::Abstained,
            feature_schema_id,
            features,
            fixed_invariants,
        )
    }

    fn new<F: Serialize, I: Serialize>(
        eligible: &[&str],
        selected: Option<&str>,
        disposition: PolicyDecisionDisposition,
        feature_schema_id: &str,
        features: &F,
        fixed_invariants: &I,
    ) -> Result<Self, KernelError> {
        Ok(Self {
            eligible_actions: eligible
                .iter()
                .map(|action| PolicyActionId((*action).to_owned()))
                .collect(),
            selected_action: selected.map(|action| PolicyActionId(action.to_owned())),
            disposition,
            selected_score_micros: None,
            propensity_ppm: (disposition == PolicyDecisionDisposition::Selected)
                .then_some(1_000_000),
            feature_schema_id: feature_schema_id.to_owned(),
            feature_digest_sha256: digest_json("core:policy-features:v1", features)?,
            fixed_invariants_digest_sha256: digest_json(
                "core:policy-fixed-invariants:v1",
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
        let events = core_record::replay_timed(self.rollout.path())?;
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
                core_record::RecordError::Io(std::io::Error::other(
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
        harness_error_code: Option<&str>,
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
            harness_error_code: harness_error_code.map(str::to_owned),
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
        let aggregate = self
            .policy_evidence
            .as_ref()
            .expect("ensured above")
            .run_aggregate();
        let join = self
            .policy_evidence
            .as_ref()
            .expect("ensured above")
            .run_join();
        let complete_usage = self.ledger.provider_attempts == self.ledger.turns;
        let input = policy_evidence_recorder::PolicyOutcomeInput {
            terminal: aggregate.terminal,
            quality_micros: aggregate.quality_micros,
            cost_microusd: policy_cost_microusd(&self.ledger.cost_state()),
            input_tokens: complete_usage.then_some(self.ledger.usage.input),
            output_tokens: complete_usage.then_some(self.ledger.usage.output),
            latency_us: aggregate.latency_us,
            verifier: aggregate.verifier,
            harness_error_code: aggregate
                .has_harness_error
                .then(|| "turn_failure".to_owned()),
        };
        let mut recorder = self.policy_evidence.take().expect("ensured above");
        let started = Instant::now();
        let result =
            recorder.append_run_outcome(&mut self.rollout, TurnId(self.seq_turn), &join, input);
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

pub(super) fn policy_harness_error_code(error: &KernelError) -> &'static str {
    match error {
        KernelError::Provider(_) => "provider_error",
        KernelError::Record(_) => "record_error",
        KernelError::InvalidRouteMetadata { .. } | KernelError::InvalidRoute(_) => "route_error",
        KernelError::ProviderRunNoticeLimit => "provider_notice_limit",
        KernelError::InvalidBudget(_) | KernelError::InferenceBudgetExhausted(_) => "budget_error",
        KernelError::InvalidSubmission(_) => "submission_error",
        KernelError::UnpricedUsdCeiling
        | KernelError::Pricing(_)
        | KernelError::PricingLedger(_) => "pricing_error",
        KernelError::InvalidPermissionPolicy(_) => "permission_error",
        KernelError::RuntimePolicyAlreadyRecorded => "runtime_policy_error",
        KernelError::UnknownEffects { .. } | KernelError::EffectJournal(_) => "effect_unknown",
        KernelError::EffectBoundary(_) => "effect_error",
        KernelError::IdentityExhausted(_) => "identity_exhausted",
        KernelError::OpaqueProviderRetries => "opaque_provider_retries",
        KernelError::ContextWindowExceeded { .. }
        | KernelError::ContextBudget(_)
        | KernelError::InstructionContextTooLarge { .. }
        | KernelError::InstructionContextAlreadyResolved
        | KernelError::EnvironmentContextTooLarge { .. }
        | KernelError::EnvironmentContextAlreadyResolved
        | KernelError::ContextResolution(_)
        | KernelError::ContextAlreadyResolved => "context_error",
        KernelError::AgentCatalogAlreadyResolved => "agent_catalog_error",
        KernelError::TunablesAlreadyResolved | KernelError::TunablesNotResolved => "tunables_error",
        KernelError::ToolingPolicy(_) => "tooling_policy_error",
        KernelError::ToolOutputSpill(_) => "tool_output_spill_error",
        KernelError::McpLifecycle(_) => "mcp_lifecycle_error",
        KernelError::PolicyEvidence(_) => "policy_evidence_error",
        KernelError::DelegationDepthExceeded => "delegation_error",
        #[cfg(test)]
        KernelError::WorkflowEngine(_) => "workflow_error",
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
    current: &core_obs::ReproducibleCounters,
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
