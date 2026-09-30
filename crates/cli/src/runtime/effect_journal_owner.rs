//! Session effect identity, unknown-outcome and recovery owner. Physical journal bytes remain
//! owned by Rollout; typed ports borrow that writer only for the actual admission/terminal barrier.
//! No executor receives mutable session, provider, configuration or policy state.
use super::KernelError;
use super::effect_descriptor::{effect_class_label, effect_workspace};
use super::route_attempt_accounting::crash_recovery_accounting;
use super::route_validation::replay_logical_rollout;
use super::tool_presentation::ui_approval_arguments;
use iteron_kernel::{effect_admission::EffectAdmissions, effect_class, effect_journal, effects};
use iteron_obs::Ledger;
use iteron_protocol::{Capability, Event, EventKind, Seq, ToolResult, ToolUse, TurnId};
use iteron_record::Rollout;
use std::{future::Future, path::Path, time::Instant};

/// Why an effect settled Unknown. Both causes remain durable and forbid automatic replay;
/// operator cancellation does not independently forbid a later explicit operator submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnknownCause {
    Unobserved,
    OperatorCancelled,
}

#[cfg(test)]
#[path = "effect_journal_owner_tests.rs"]
mod tests;

pub(super) struct EffectJournalOwner {
    admissions: EffectAdmissions,
    unresolved: usize,
    replay_required: bool,
    workspace_mutated: bool,
    pending: usize,
    observation_unknown: bool,
    barrier_failed: bool,
}

impl Default for EffectJournalOwner {
    fn default() -> Self {
        Self {
            admissions: EffectAdmissions::default(),
            unresolved: 0,
            replay_required: true,
            workspace_mutated: false,
            pending: 0,
            observation_unknown: false,
            barrier_failed: false,
        }
    }
}

impl EffectJournalOwner {
    pub(super) fn begin_operator_turn(&mut self) {
        self.workspace_mutated = false;
    }
    pub(super) fn note_workspace_mutation(&mut self) {
        self.workspace_mutated = true;
    }
    pub(super) fn note_tool_capability(&mut self, capability: Capability) {
        self.workspace_mutated |= capability != Capability::ReadOnly;
    }
    pub(super) fn workspace_mutated(&self) -> bool {
        self.workspace_mutated
    }
    pub(super) fn unresolved_count(&self) -> usize {
        self.unresolved
    }
    /// Admission-blocking count is intentionally a different fact. An explicit cancellation can
    /// permit later operator work while still lacking physical evidence for the parent's terminal.
    pub(super) fn parent_settlement_known(&self) -> bool {
        !self.replay_required
            && self.pending == 0
            && !self.observation_unknown
            && !self.barrier_failed
    }
    pub(super) fn retain_live_followup(&mut self) {
        self.replay_required = false;
    }
    pub(super) fn adopt_journal(&mut self) {
        *self = Self::default();
    }
    pub(super) fn next_ordinal(&mut self, turn: TurnId, class: effect_class::EffectClass) -> usize {
        self.admissions.next_ordinal(turn, class)
    }

    /// This port records existing authority. Capability is supplied only after the real operation
    /// gate; the owner cannot approve a proposal or widen an executor's inherited ceiling.
    pub(super) fn open(
        &mut self,
        rollout: &mut Rollout,
        effect: effects::BrokeredEffect,
    ) -> Result<effects::EffectTicket, effects::BrokerError> {
        match effects::open_effect(rollout, &mut self.admissions, effect) {
            Ok(ticket) => {
                self.pending = self.pending.saturating_add(1);
                Ok(ticket)
            }
            Err(error) => {
                self.barrier_failed |= matches!(&error, effects::BrokerError::Record(_));
                Err(error)
            }
        }
    }

    pub(super) fn open_tool(
        &mut self,
        rollout: &mut Rollout,
        workspace: &Path,
        turn: TurnId,
        ordinal: usize,
        call: &ToolUse,
        capability: Capability,
    ) -> Result<effects::EffectTicket, effects::BrokerError> {
        self.note_tool_capability(capability);
        self.open(
            rollout,
            effects::BrokeredEffect {
                turn,
                effect_id: effect_class::effect_id(
                    turn,
                    effect_class::EffectClass::RegistryTool,
                    ordinal,
                ),
                tool_use_id: call.id.clone(),
                kind: call.name.clone(),
                capability,
                audit_arguments: ui_approval_arguments(&call.input),
                workspace: effect_workspace(workspace),
                provider_route_attempt: None,
            },
        )
    }

    pub(super) fn settle(
        &mut self,
        rollout: &mut Rollout,
        ticket: effects::EffectTicket,
        settlement: effects::Settlement,
        cause: UnknownCause,
    ) -> Result<(), effects::BrokerError> {
        let blocks = matches!(&settlement, effects::Settlement::Unknown(_))
            && cause == UnknownCause::Unobserved;
        self.commit_settlement(rollout, ticket, settlement, blocks)
    }

    /// A definite tool completion uses the exact admitted ticket identity. The live ledger is
    /// downstream of this port; a failed terminal cannot manufacture reproducible tool counts.
    pub(super) fn settle_tool(
        &mut self,
        rollout: &mut Rollout,
        ticket: effects::EffectTicket,
        tool: &str,
        result: &ToolResult,
    ) -> Result<(), effects::BrokerError> {
        let effect_id = ticket.effect_id().clone();
        self.settle(
            rollout,
            ticket,
            effects::Settlement::Definite(EventKind::ToolDone {
                result: result.clone(),
                effect_id: Some(effect_id),
                tool: Some(tool.to_owned()),
            }),
            UnknownCause::Unobserved,
        )
    }

    pub(super) async fn broker<Execute, ExecuteFuture, T>(
        &mut self,
        rollout: &mut Rollout,
        effect: effects::BrokeredEffect,
        execute: Execute,
    ) -> Result<effects::BrokeredOutcome<T>, effects::BrokerError>
    where
        Execute: FnOnce() -> ExecuteFuture,
        ExecuteFuture: Future<Output = effects::EffectDisposition<T>>,
    {
        // Existing non-registry broker callers own their observed outcome projection. Their
        // declared kind controls recovery blocking; optional telemetry is never turn authority.
        let blocks = effect_journal::kind_blocks_resume(&effect.kind);
        let ticket = self.open(rollout, effect)?;
        let (settlement, outcome) = match execute().await {
            effects::EffectDisposition::Definite { terminal, value } => (
                effects::Settlement::Definite(terminal),
                effects::BrokeredOutcome::Definite(value),
            ),
            effects::EffectDisposition::Unknown { reason, value } => (
                effects::Settlement::Unknown(reason),
                effects::BrokeredOutcome::Unknown(value),
            ),
        };
        let blocks = blocks && matches!(&outcome, effects::BrokeredOutcome::Unknown(_));
        self.commit_settlement(rollout, ticket, settlement, blocks)?;
        Ok(outcome)
    }

    fn commit_settlement(
        &mut self,
        rollout: &mut Rollout,
        ticket: effects::EffectTicket,
        settlement: effects::Settlement,
        blocks: bool,
    ) -> Result<(), effects::BrokerError> {
        let unknown = matches!(
            &settlement,
            effects::Settlement::Unknown(_)
                | effects::Settlement::Definite(EventKind::EffectUnknown { .. })
        );
        match effects::settle_effect(rollout, ticket, settlement) {
            Ok(()) => {
                self.pending = self.pending.saturating_sub(1);
                self.observation_unknown |= unknown;
                if blocks {
                    self.unresolved = self.unresolved.saturating_add(1);
                }
                Ok(())
            }
            Err(error) => {
                self.barrier_failed |= matches!(&error, effects::BrokerError::Record(_));
                Err(error)
            }
        }
    }

    /// Restore the actual canonical WAL once for a new/adopted process. Durable orphan intents
    /// become Unknown before future admission; missing provider route identity is refused before
    /// any recovery append. Partial publication keeps replay_required, so a subsequent fold sees
    /// already-confirmed terminals instead of appending a second terminal or retrying an executor.
    pub(super) fn guard_recovery(
        &mut self,
        rollout: &mut Rollout,
        ledger: &mut Ledger,
    ) -> Result<(), KernelError> {
        if !self.replay_required {
            return self.require_known();
        }
        let events = replay_logical_rollout(rollout.path())?;
        let journal = effects::EffectJournal::replay(&events)?;
        self.admissions = EffectAdmissions::from_journal(&journal);
        let pending = journal.pending();
        self.pending = pending.len();
        self.observation_unknown |= journal.unknown_count() != 0;
        if pending.iter().any(|effect| {
            effect.tool == effect_class_label(effect_class::EffectClass::Provider)
                && effect.provider_route_attempt.is_none()
        }) {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_route_attempt",
                reason: "pending legacy provider intent has no pre-dispatch route identity",
            });
        }
        for effect in &pending {
            let event = Event {
                seq: Seq::ZERO,
                turn: effect.turn,
                kind: EventKind::EffectUnknown {
                    id: effect.id.clone(),
                    tool: effect.tool.clone(),
                    reason: "recovery found a durable intent without a durable tool result; automatic retry is forbidden".into(),
                    provider_route_attempt: effect
                        .provider_route_attempt
                        .clone()
                        .map(crash_recovery_accounting),
                },
            };
            let started = Instant::now();
            let appended = rollout.append(&event);
            ledger.record_fsync_latency_us(
                u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            );
            if let Err(error) = appended {
                self.barrier_failed = true;
                return Err(error.into());
            }
            self.pending = self.pending.saturating_sub(1);
            self.observation_unknown = true;
        }
        self.unresolved = journal.unknown_requiring_reconciliation().saturating_add(
            pending
                .iter()
                .filter(|effect| effect_journal::kind_blocks_resume(&effect.tool))
                .count(),
        );
        self.replay_required = false;
        self.require_known()
    }

    fn require_known(&self) -> Result<(), KernelError> {
        if self.unresolved_count() == 0 {
            Ok(())
        } else {
            Err(KernelError::UnknownEffects {
                count: self.unresolved,
            })
        }
    }
}
