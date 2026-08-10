//! Run-local construction of content-free policy decision and terminal outcome evidence.
//!
//! The recorder owns opportunity identity, ordering, and joins. Callers supply only typed policy
//! inputs; they cannot choose an ordinal, timestamp, run identity, tunables identity, or outcome
//! commitment. State advances only after the owning [`core_record::Rollout`] has fsynced the
//! evidence, and reopening a rollout reconstructs the joins and terminal guards from replay.

#[path = "policy_evidence_recorder/digest.rs"]
mod digest;
#[path = "policy_evidence_recorder/restore.rs"]
mod restore;
#[path = "policy_evidence_recorder/types.rs"]
mod types;

pub(crate) use types::*;

use core_protocol::{
    EventKind, MAX_POLICY_ACTIONS, POLICY_DECISION_EVIDENCE_SCHEMA_VERSION,
    POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION, PolicyDecisionDisposition, PolicyDecisionEvidence,
    PolicyEvidenceError, PolicyOpportunityId, PolicyOutcomeEvidence, PolicyOutcomeScope,
    PolicyRuntimeIdentity, RunId, Seq, TurnId,
};
use digest::{OrderedOpportunityDigest, opportunity_id};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
#[path = "policy_evidence_recorder/tests.rs"]
mod tests;

const MAX_RUN_POLICY_OPPORTUNITIES: usize = MAX_POLICY_ACTIONS * 16;
static NEXT_RECORDER_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OpportunityStatus {
    Pending,
    Decided,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OpportunityState {
    turn_id: Option<TurnId>,
    slot: FrozenPolicySlot,
    status: OpportunityStatus,
}

/// One state machine per held rollout writer. There are no setters for its immutable identities.
pub(crate) struct PolicyEvidenceRecorder {
    recorder_id: u64,
    run_id: RunId,
    tunables_digest_sha256: String,
    policies: Vec<PolicyRuntimeIdentity>,
    next_opportunity_sequence: u64,
    next_decision_ordinal: u64,
    next_outcome_ordinal: u64,
    /// Monotonic only inside the currently open writer segment. Resume deliberately resets it.
    last_decided_at_us: Option<u64>,
    opportunities: BTreeMap<PolicyOpportunityId, OpportunityState>,
    run_join: OrderedOpportunityDigest,
    turn_joins: BTreeMap<u32, OrderedOpportunityDigest>,
    terminal_turns: BTreeSet<u32>,
    run_terminal: bool,
    run_aggregate: PolicyRunAggregate,
    turn_started_at_us: BTreeMap<u32, u64>,
}

impl PolicyEvidenceRecorder {
    /// Bind one run to one tunables resolution and exactly one runtime identity for each frozen
    /// strategy slot. All policies must name the same immutable bundle.
    pub(crate) fn new(
        run_id: RunId,
        tunables_digest_sha256: String,
        bindings: Vec<FrozenSlotPolicyBinding>,
    ) -> Result<Self, PolicyEvidenceRecorderError> {
        validate_machine_id(&run_id.0, "run_id")?;
        validate_digest(&tunables_digest_sha256)?;

        let mut by_slot = vec![None; FROZEN_POLICY_SLOT_COUNT];
        let mut bundle_identity: Option<(&str, &str)> = None;
        for binding in &bindings {
            let slot = FrozenPolicySlot::parse(&binding.slot)
                .ok_or_else(|| PolicyEvidenceRecorderError::UnknownSlot(binding.slot.clone()))?;
            binding.policy.validate()?;
            if let Some((bundle_id, bundle_digest)) = bundle_identity {
                if binding.policy.bundle_id != bundle_id
                    || binding.policy.bundle_digest_sha256 != bundle_digest
                {
                    return Err(PolicyEvidenceRecorderError::BundleIdentityMismatch);
                }
            } else {
                bundle_identity = Some((
                    binding.policy.bundle_id.as_str(),
                    binding.policy.bundle_digest_sha256.as_str(),
                ));
            }
            let cell = &mut by_slot[slot.index()];
            if cell.is_some() {
                return Err(PolicyEvidenceRecorderError::DuplicateSlot(
                    binding.slot.clone(),
                ));
            }
            *cell = Some(binding.policy.clone());
        }

        let mut policies = Vec::with_capacity(FROZEN_POLICY_SLOT_COUNT);
        for (index, policy) in by_slot.into_iter().enumerate() {
            let Some(policy) = policy else {
                return Err(PolicyEvidenceRecorderError::MissingSlot(
                    FROZEN_POLICY_SLOT_NAMES[index],
                ));
            };
            policies.push(policy);
        }

        Ok(Self {
            recorder_id: allocate_recorder_id()?,
            run_id,
            tunables_digest_sha256,
            policies,
            next_opportunity_sequence: 0,
            next_decision_ordinal: 0,
            next_outcome_ordinal: 0,
            last_decided_at_us: None,
            opportunities: BTreeMap::new(),
            run_join: OrderedOpportunityDigest::default(),
            turn_joins: BTreeMap::new(),
            terminal_turns: BTreeSet::new(),
            run_terminal: false,
            run_aggregate: PolicyRunAggregate::default(),
            turn_started_at_us: BTreeMap::new(),
        })
    }

    /// Mint a bounded token before one frozen-slot decision. A terminal scope cannot be reopened.
    pub(crate) fn begin_opportunity(
        &mut self,
        slot_id: &core_protocol::slot::SlotId,
        turn_id: Option<TurnId>,
    ) -> Result<PolicyOpportunity, PolicyEvidenceRecorderError> {
        if self.run_terminal {
            return Err(PolicyEvidenceRecorderError::RunAlreadyTerminal);
        }
        if let Some(turn) = turn_id
            && self.terminal_turns.contains(&turn.0)
        {
            return Err(PolicyEvidenceRecorderError::TurnAlreadyTerminal(turn));
        }
        let slot = FrozenPolicySlot::parse(slot_id)
            .ok_or_else(|| PolicyEvidenceRecorderError::UnknownSlot(slot_id.clone()))?;
        if self.opportunities.len() >= MAX_RUN_POLICY_OPPORTUNITIES {
            return Err(PolicyEvidenceRecorderError::TooManyOpportunities);
        }
        let policy = self
            .policies
            .get(slot.index())
            .ok_or(PolicyEvidenceRecorderError::MissingSlot(slot.name()))?;
        let sequence = self.next_opportunity_sequence;
        let id = opportunity_id(
            self.recorder_id,
            sequence,
            &self.run_id.0,
            &self.tunables_digest_sha256,
            slot.name(),
            &policy.bundle_digest_sha256,
            &policy.policy_digest_sha256,
        );
        if self.opportunities.contains_key(&id) {
            return Err(PolicyEvidenceRecorderError::CounterExhausted);
        }
        self.next_opportunity_sequence = sequence
            .checked_add(1)
            .ok_or(PolicyEvidenceRecorderError::CounterExhausted)?;
        self.opportunities.insert(
            id.clone(),
            OpportunityState {
                turn_id,
                slot,
                status: OpportunityStatus::Pending,
            },
        );
        Ok(PolicyOpportunity {
            recorder_id: self.recorder_id,
            run_id: self.run_id.clone(),
            opportunity_id: id,
        })
    }

    /// Validate, durably append, then commit exactly one decision. An append failure leaves the
    /// opportunity pending and the rollout writer owns its ordinary fail-stop recovery semantics.
    pub(crate) fn append_decision(
        &mut self,
        rollout: &mut core_record::Rollout,
        opportunity: &PolicyOpportunity,
        input: PolicyDecisionInput,
    ) -> Result<Seq, PolicyEvidenceRecorderError> {
        if opportunity.run_id != self.run_id {
            return Err(PolicyEvidenceRecorderError::CrossRunOpportunity);
        }
        if opportunity.recorder_id != self.recorder_id {
            return Err(PolicyEvidenceRecorderError::CrossRecorderOpportunity);
        }
        let state = self
            .opportunities
            .get(&opportunity.opportunity_id)
            .copied()
            .ok_or_else(|| {
                PolicyEvidenceRecorderError::UnknownOpportunity(opportunity.opportunity_id.clone())
            })?;
        if state.status == OpportunityStatus::Decided {
            return Err(PolicyEvidenceRecorderError::DuplicateOpportunity(
                opportunity.opportunity_id.clone(),
            ));
        }
        if input.disposition == PolicyDecisionDisposition::Selected {
            let selected = input.selected_action.as_ref().ok_or(
                PolicyEvidenceRecorderError::InvalidEvidence(PolicyEvidenceError::InvalidSelection),
            )?;
            if !input.eligible_actions.contains(selected) {
                return Err(PolicyEvidenceRecorderError::SelectedActionNotEligible(
                    selected.clone(),
                ));
            }
        }

        let decided_at_us = self.next_decided_at_us(rollout.segment_elapsed_us())?;
        let decision_ordinal = self.next_decision_ordinal;
        let policy = self
            .policies
            .get(state.slot.index())
            .cloned()
            .ok_or(PolicyEvidenceRecorderError::MissingSlot(state.slot.name()))?;
        let evidence = PolicyDecisionEvidence {
            schema_version: POLICY_DECISION_EVIDENCE_SCHEMA_VERSION,
            opportunity_id: opportunity.opportunity_id.clone(),
            run_id: self.run_id.clone(),
            turn_id: state.turn_id,
            slot: core_protocol::slot::SlotId(state.slot.name().to_owned()),
            policy,
            eligible_actions: input.eligible_actions,
            selected_action: input.selected_action,
            disposition: input.disposition,
            selected_score_micros: input.selected_score_micros,
            propensity_ppm: input.propensity_ppm,
            feature_schema_id: input.feature_schema_id,
            feature_digest_sha256: input.feature_digest_sha256,
            fixed_invariants_digest_sha256: input.fixed_invariants_digest_sha256,
            tunables_digest_sha256: self.tunables_digest_sha256.clone(),
            decision_ordinal,
            decided_at_us,
        };
        evidence.validate()?;

        let next_decision_ordinal = decision_ordinal
            .checked_add(1)
            .ok_or(PolicyEvidenceRecorderError::CounterExhausted)?;
        let event = EventKind::PolicyDecision {
            evidence: evidence.clone(),
        };
        let seq = rollout.append(&core_protocol::Event {
            seq: Seq::ZERO,
            turn: state.turn_id.unwrap_or(TurnId(0)),
            kind: event,
        })?;

        self.next_decision_ordinal = next_decision_ordinal;
        self.last_decided_at_us = Some(decided_at_us);
        self.run_join.append(&opportunity.opportunity_id);
        if let Some(turn) = state.turn_id {
            self.turn_joins
                .entry(turn.0)
                .or_default()
                .append(&opportunity.opportunity_id);
        }
        if let Some(stored) = self.opportunities.get_mut(&opportunity.opportunity_id) {
            stored.status = OpportunityStatus::Decided;
        }
        Ok(seq)
    }

    pub(crate) fn turn_join(&self, turn: TurnId) -> PolicyOpportunityJoin {
        join(self.turn_joins.get(&turn.0))
    }

    pub(crate) fn run_join(&self) -> PolicyOpportunityJoin {
        join(Some(&self.run_join))
    }

    pub(crate) fn append_turn_outcome(
        &mut self,
        rollout: &mut core_record::Rollout,
        turn: TurnId,
        expected_join: &PolicyOpportunityJoin,
        input: PolicyOutcomeInput,
    ) -> Result<Seq, PolicyEvidenceRecorderError> {
        if self.run_terminal {
            return Err(PolicyEvidenceRecorderError::RunAlreadyTerminal);
        }
        if self.terminal_turns.contains(&turn.0) {
            return Err(PolicyEvidenceRecorderError::TurnAlreadyTerminal(turn));
        }
        if self.has_pending(Some(turn)) {
            return Err(PolicyEvidenceRecorderError::PendingOpportunities);
        }
        let actual = self.turn_join(turn);
        if &actual != expected_join {
            return Err(PolicyEvidenceRecorderError::OutcomeJoinMismatch);
        }
        let aggregate_input = input.clone();
        let (event, next_ordinal) =
            self.outcome_event(PolicyOutcomeScope::Turn, Some(turn), actual, input)?;
        let seq = rollout.append(&core_protocol::Event {
            seq: Seq::ZERO,
            turn,
            kind: event,
        })?;
        self.next_outcome_ordinal = next_ordinal;
        self.terminal_turns.insert(turn.0);
        self.absorb_turn_input(&aggregate_input);
        Ok(seq)
    }

    pub(crate) fn append_run_outcome(
        &mut self,
        rollout: &mut core_record::Rollout,
        event_turn: TurnId,
        expected_join: &PolicyOpportunityJoin,
        input: PolicyOutcomeInput,
    ) -> Result<Seq, PolicyEvidenceRecorderError> {
        if self.run_terminal {
            return Err(PolicyEvidenceRecorderError::RunAlreadyTerminal);
        }
        if self.has_pending(None) {
            return Err(PolicyEvidenceRecorderError::PendingOpportunities);
        }
        for turn in self.turn_joins.keys().copied() {
            if !self.terminal_turns.contains(&turn) {
                return Err(PolicyEvidenceRecorderError::MissingTurnOutcome(TurnId(
                    turn,
                )));
            }
        }
        let actual = self.run_join();
        if &actual != expected_join {
            return Err(PolicyEvidenceRecorderError::OutcomeJoinMismatch);
        }
        if input.terminal != self.run_aggregate.terminal
            || input.quality_micros != self.run_aggregate.quality_micros
            || input.latency_us != self.run_aggregate.latency_us
            || input.verifier != self.run_aggregate.verifier
            || input.harness_error_code.is_some() != self.run_aggregate.has_harness_error
        {
            return Err(PolicyEvidenceRecorderError::ReplayInvariant(
                "run outcome does not aggregate its terminal turn evidence",
            ));
        }
        let (event, next_ordinal) =
            self.outcome_event(PolicyOutcomeScope::Run, None, actual, input)?;
        let seq = rollout.append(&core_protocol::Event {
            seq: Seq::ZERO,
            turn: event_turn,
            kind: event,
        })?;
        self.next_outcome_ordinal = next_ordinal;
        self.run_terminal = true;
        Ok(seq)
    }

    fn outcome_event(
        &mut self,
        scope: PolicyOutcomeScope,
        turn_id: Option<TurnId>,
        join: PolicyOpportunityJoin,
        input: PolicyOutcomeInput,
    ) -> Result<(EventKind, u64), PolicyEvidenceRecorderError> {
        let ordinal = self.next_outcome_ordinal;
        let evidence = PolicyOutcomeEvidence {
            schema_version: POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION,
            scope,
            run_id: self.run_id.clone(),
            turn_id,
            terminal: input.terminal,
            opportunity_count: join.opportunity_count,
            opportunities_digest_sha256: join.opportunities_digest_sha256,
            quality_micros: input.quality_micros,
            cost_microusd: input.cost_microusd,
            input_tokens: input.input_tokens,
            output_tokens: input.output_tokens,
            latency_us: input.latency_us,
            verifier: input.verifier,
            harness_error_code: input.harness_error_code,
            outcome_ordinal: ordinal,
        };
        evidence.validate()?;
        let next_ordinal = ordinal
            .checked_add(1)
            .ok_or(PolicyEvidenceRecorderError::CounterExhausted)?;
        Ok((EventKind::PolicyOutcome { evidence }, next_ordinal))
    }

    fn has_pending(&self, turn: Option<TurnId>) -> bool {
        self.opportunities.values().any(|state| {
            state.status == OpportunityStatus::Pending
                && turn.is_none_or(|expected| state.turn_id == Some(expected))
        })
    }

    fn next_decided_at_us(&self, elapsed: u64) -> Result<u64, PolicyEvidenceRecorderError> {
        match self.last_decided_at_us {
            Some(last) => Ok(elapsed.max(
                last.checked_add(1)
                    .ok_or(PolicyEvidenceRecorderError::CounterExhausted)?,
            )),
            None => Ok(elapsed),
        }
    }

    /// Observe a successfully appended provider-turn start. The timestamp shares the rollout
    /// segment origin; an already-restored open turn starts at zero in the new segment.
    pub(crate) fn observe_turn_start(&mut self, turn: TurnId, started_at_us: u64) {
        self.turn_started_at_us
            .entry(turn.0)
            .or_insert(started_at_us);
    }

    pub(crate) fn turn_latency_us(&self, turn: TurnId, now_us: u64) -> u64 {
        now_us.saturating_sub(self.turn_started_at_us.get(&turn.0).copied().unwrap_or(0))
    }

    pub(crate) fn is_turn_terminal(&self, turn: TurnId) -> bool {
        self.terminal_turns.contains(&turn.0)
    }

    pub(crate) fn is_run_terminal(&self) -> bool {
        self.run_terminal
    }
}

fn join(state: Option<&OrderedOpportunityDigest>) -> PolicyOpportunityJoin {
    let state = state.cloned().unwrap_or_default();
    PolicyOpportunityJoin {
        opportunity_count: state.count(),
        opportunities_digest_sha256: state.hex_digest(),
    }
}

fn allocate_recorder_id() -> Result<u64, PolicyEvidenceRecorderError> {
    NEXT_RECORDER_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| PolicyEvidenceRecorderError::CounterExhausted)
}

fn validate_digest(value: &str) -> Result<(), PolicyEvidenceRecorderError> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    valid
        .then_some(())
        .ok_or_else(|| PolicyEvidenceError::InvalidDigest.into())
}

fn validate_machine_id(
    value: &str,
    field: &'static str,
) -> Result<(), PolicyEvidenceRecorderError> {
    let valid = !value.is_empty()
        && value.len() <= core_protocol::MAX_POLICY_MACHINE_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'+')
        });
    valid
        .then_some(())
        .ok_or_else(|| PolicyEvidenceError::InvalidMachineId(field).into())
}
