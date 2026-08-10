use super::{
    FrozenPolicySlot, FrozenSlotPolicyBinding, MAX_RUN_POLICY_OPPORTUNITIES, OpportunityState,
    OpportunityStatus, PolicyEvidenceRecorder, PolicyEvidenceRecorderError, PolicyOutcomeInput,
    PolicyRunAggregate, join,
};
use core_protocol::{
    EventKind, PolicyOutcomeScope, PolicyTerminalOutcome, PolicyVerifierOutcome, RunId, TurnId,
};
use sha2::{Digest, Sha256};

const MAX_POLICY_RUN_SEGMENTS: usize = 1_024;

impl PolicyEvidenceRecorder {
    /// Validate every completed policy-run segment in a physical rollout, then either restore its
    /// crash-open final segment or begin a deterministic new segment after a graceful session
    /// close. A terminal run is never reopened and two session actors never reuse a policy run id.
    pub(crate) fn restore_or_begin(
        rollout_run_id: &RunId,
        tunables_digest_sha256: String,
        bindings: Vec<FrozenSlotPolicyBinding>,
        events: &[core_record::TimedEvent],
    ) -> Result<Self, PolicyEvidenceRecorderError> {
        let mut groups: Vec<(RunId, Vec<core_record::TimedEvent>)> = Vec::new();
        for timed in events {
            let Some(run_id) = policy_event_run_id(&timed.event.kind) else {
                continue;
            };
            match groups.last_mut() {
                Some((current, group)) if current == run_id => group.push(timed.clone()),
                _ => {
                    if groups.len() >= MAX_POLICY_RUN_SEGMENTS {
                        return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                            "policy run segment bound was exceeded",
                        ));
                    }
                    let expected = policy_run_id(rollout_run_id, groups.len());
                    if *run_id != expected {
                        return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                            "policy run segments are missing, repeated, or out of order",
                        ));
                    }
                    groups.push((run_id.clone(), vec![timed.clone()]));
                }
            }
        }

        if groups.is_empty() {
            return Self::new(
                policy_run_id(rollout_run_id, 0),
                tunables_digest_sha256,
                bindings,
            );
        }

        let group_count = groups.len();
        let mut latest = None;
        for (index, (run_id, group)) in groups.into_iter().enumerate() {
            let restored = Self::restore(
                run_id,
                tunables_digest_sha256.clone(),
                bindings.clone(),
                &group,
            )?;
            if index + 1 < group_count && !restored.is_run_terminal() {
                return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                    "a later policy run begins before the previous run is terminal",
                ));
            }
            latest = Some(restored);
        }
        let latest = latest.expect("a non-empty group list has a final recorder");
        if latest.is_run_terminal() {
            Self::new(
                policy_run_id(rollout_run_id, group_count),
                tunables_digest_sha256,
                bindings,
            )
        } else {
            Ok(latest)
        }
    }

    /// Rebuild the run-local state machine from the hash-verified rollout while its exclusive
    /// writer is held. Non-policy events are ignored except that a restored open turn begins at
    /// the new descriptor's segment origin rather than pretending two monotonic clocks join.
    pub(crate) fn restore(
        run_id: RunId,
        tunables_digest_sha256: String,
        bindings: Vec<FrozenSlotPolicyBinding>,
        events: &[core_record::TimedEvent],
    ) -> Result<Self, PolicyEvidenceRecorderError> {
        let mut recorder = Self::new(run_id, tunables_digest_sha256, bindings)?;
        for timed in events {
            match &timed.event.kind {
                EventKind::PolicyDecision { evidence } => {
                    recorder.restore_decision(timed, evidence)?;
                }
                EventKind::PolicyOutcome { evidence } => {
                    recorder.restore_outcome(timed, evidence)?;
                }
                _ => {}
            }
        }
        // A reopened Rollout owns a new monotonic segment. Historical offsets remain in their
        // events but cannot be used as the lower bound for decisions written by this descriptor.
        recorder.last_decided_at_us = None;
        recorder.turn_started_at_us.clear();
        Ok(recorder)
    }

    fn restore_decision(
        &mut self,
        timed: &core_record::TimedEvent,
        evidence: &core_protocol::PolicyDecisionEvidence,
    ) -> Result<(), PolicyEvidenceRecorderError> {
        evidence.validate()?;
        if self.run_terminal {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "decision appears after the run outcome",
            ));
        }
        if evidence.run_id != self.run_id {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "decision run identity differs from the held rollout",
            ));
        }
        if evidence.tunables_digest_sha256 != self.tunables_digest_sha256 {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "decision tunables identity differs from the pinned checkpoint",
            ));
        }
        if evidence.decision_ordinal != self.next_decision_ordinal {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "decision ordinals are not contiguous",
            ));
        }
        let slot = FrozenPolicySlot::parse(&evidence.slot)
            .ok_or_else(|| PolicyEvidenceRecorderError::UnknownSlot(evidence.slot.clone()))?;
        if self.policies.get(slot.index()) != Some(&evidence.policy) {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "decision policy identity differs from the compiled checkpoint",
            ));
        }
        if evidence
            .turn_id
            .is_some_and(|turn| self.terminal_turns.contains(&turn.0) || timed.event.turn != turn)
        {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "decision turn identity is terminal or disagrees with its event envelope",
            ));
        }
        let Some(line_ts_us) = timed.ts_us else {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "policy decision has no record-segment timestamp",
            ));
        };
        if evidence.decided_at_us > line_ts_us {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "decision timestamp is later than its durable chain line",
            ));
        }
        if self.opportunities.len() >= MAX_RUN_POLICY_OPPORTUNITIES {
            return Err(PolicyEvidenceRecorderError::TooManyOpportunities);
        }
        if self
            .opportunities
            .insert(
                evidence.opportunity_id.clone(),
                OpportunityState {
                    turn_id: evidence.turn_id,
                    slot,
                    status: OpportunityStatus::Decided,
                },
            )
            .is_some()
        {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "duplicate policy opportunity identity",
            ));
        }
        self.run_join.append(&evidence.opportunity_id);
        if let Some(turn) = evidence.turn_id {
            self.turn_joins
                .entry(turn.0)
                .or_default()
                .append(&evidence.opportunity_id);
        }
        self.next_decision_ordinal = self
            .next_decision_ordinal
            .checked_add(1)
            .ok_or(PolicyEvidenceRecorderError::CounterExhausted)?;
        Ok(())
    }

    fn restore_outcome(
        &mut self,
        timed: &core_record::TimedEvent,
        evidence: &core_protocol::PolicyOutcomeEvidence,
    ) -> Result<(), PolicyEvidenceRecorderError> {
        evidence.validate()?;
        if evidence.run_id != self.run_id || evidence.outcome_ordinal != self.next_outcome_ordinal {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "outcome run identity or ordinal disagrees with replay state",
            ));
        }
        match evidence.scope {
            PolicyOutcomeScope::Turn => {
                let turn = evidence
                    .turn_id
                    .ok_or(PolicyEvidenceRecorderError::ReplayInvariant(
                        "turn outcome is missing its turn identity",
                    ))?;
                if timed.event.turn != turn || !self.terminal_turns.insert(turn.0) {
                    return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                        "turn outcome envelope disagrees or is duplicated",
                    ));
                }
                let actual = join(self.turn_joins.get(&turn.0));
                if actual.opportunity_count != evidence.opportunity_count
                    || actual.opportunities_digest_sha256 != evidence.opportunities_digest_sha256
                {
                    return Err(PolicyEvidenceRecorderError::OutcomeJoinMismatch);
                }
                self.absorb_turn_evidence(evidence);
            }
            PolicyOutcomeScope::Run => {
                if self.run_terminal {
                    return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                        "run outcome is duplicated",
                    ));
                }
                for turn in self.turn_joins.keys().copied() {
                    if !self.terminal_turns.contains(&turn) {
                        return Err(PolicyEvidenceRecorderError::MissingTurnOutcome(TurnId(
                            turn,
                        )));
                    }
                }
                let actual = join(Some(&self.run_join));
                if actual.opportunity_count != evidence.opportunity_count
                    || actual.opportunities_digest_sha256 != evidence.opportunities_digest_sha256
                {
                    return Err(PolicyEvidenceRecorderError::OutcomeJoinMismatch);
                }
                if evidence.terminal != self.run_aggregate.terminal
                    || evidence.quality_micros != self.run_aggregate.quality_micros
                    || evidence.latency_us != self.run_aggregate.latency_us
                    || evidence.verifier != self.run_aggregate.verifier
                    || evidence.harness_error_code.is_some() != self.run_aggregate.has_harness_error
                {
                    return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                        "run outcome does not aggregate its terminal turn evidence",
                    ));
                }
                self.run_terminal = true;
            }
        }
        self.next_outcome_ordinal = self
            .next_outcome_ordinal
            .checked_add(1)
            .ok_or(PolicyEvidenceRecorderError::CounterExhausted)?;
        Ok(())
    }

    pub(super) fn absorb_turn_input(&mut self, input: &PolicyOutcomeInput) {
        self.absorb_turn(
            input.terminal,
            input.quality_micros,
            input.latency_us,
            input.verifier,
            input.harness_error_code.is_some(),
        );
    }

    fn absorb_turn_evidence(&mut self, evidence: &core_protocol::PolicyOutcomeEvidence) {
        self.absorb_turn(
            evidence.terminal,
            evidence.quality_micros,
            evidence.latency_us,
            evidence.verifier,
            evidence.harness_error_code.is_some(),
        );
    }

    fn absorb_turn(
        &mut self,
        terminal: PolicyTerminalOutcome,
        quality_micros: Option<i64>,
        latency_us: u64,
        verifier: PolicyVerifierOutcome,
        has_harness_error: bool,
    ) {
        if terminal_rank(terminal) > terminal_rank(self.run_aggregate.terminal) {
            self.run_aggregate.terminal = terminal;
        }
        self.run_aggregate.quality_micros = if self.run_aggregate.completed_turns == 0 {
            quality_micros
        } else {
            self.run_aggregate
                .quality_micros
                .zip(quality_micros)
                .map(|(current, next)| current.min(next))
        };
        self.run_aggregate.latency_us = self.run_aggregate.latency_us.saturating_add(latency_us);
        if verifier_rank(verifier) > verifier_rank(self.run_aggregate.verifier) {
            self.run_aggregate.verifier = verifier;
        }
        self.run_aggregate.has_harness_error |= has_harness_error;
        self.run_aggregate.completed_turns = self.run_aggregate.completed_turns.saturating_add(1);
    }

    pub(crate) fn run_aggregate(&self) -> PolicyRunAggregate {
        self.run_aggregate
    }
}

fn policy_event_run_id(kind: &EventKind) -> Option<&RunId> {
    match kind {
        EventKind::PolicyDecision { evidence } => Some(&evidence.run_id),
        EventKind::PolicyOutcome { evidence } => Some(&evidence.run_id),
        _ => None,
    }
}

fn policy_run_id(rollout_run_id: &RunId, segment: usize) -> RunId {
    if segment == 0 {
        return rollout_run_id.clone();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"core-policy-run-segment-v1\0");
    hasher.update(
        u64::try_from(rollout_run_id.0.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(rollout_run_id.0.as_bytes());
    hasher.update(u64::try_from(segment).unwrap_or(u64::MAX).to_be_bytes());
    RunId(format!("policy-run:{}", hex::encode(hasher.finalize())))
}

const fn terminal_rank(outcome: PolicyTerminalOutcome) -> u8 {
    match outcome {
        PolicyTerminalOutcome::Succeeded => 0,
        PolicyTerminalOutcome::Cancelled => 1,
        PolicyTerminalOutcome::Interrupted => 2,
        PolicyTerminalOutcome::BudgetExhausted => 3,
        PolicyTerminalOutcome::Failed => 4,
    }
}

const fn verifier_rank(outcome: PolicyVerifierOutcome) -> u8 {
    match outcome {
        PolicyVerifierOutcome::NotRun => 0,
        PolicyVerifierOutcome::Passed => 1,
        PolicyVerifierOutcome::Cancelled => 2,
        PolicyVerifierOutcome::TestFailure => 3,
        PolicyVerifierOutcome::TimedOut => 4,
        PolicyVerifierOutcome::InfrastructureFailure => 5,
    }
}
