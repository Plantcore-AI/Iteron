//! Physical writer adapter for registry tool admission and terminal facts. The domain journal,
//! ledger and failure memory stay their single real owners; executors never receive these ports.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::effect_journal_owner::{EffectJournalOwner, UnknownCause};
use super::failed_action_cache::FailedActionCache;
use super::stream_tool_events::StreamToolEvents;
use super::stream_tool_journal::StreamToolJournal;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_kernel::{effect_class, effects};
use iteron_obs::Ledger;
use iteron_protocol::{
    Capability, Event, EventKind, LifecyclePayload, RunId, Seq, TenantId, ToolResult, ToolUse,
    TurnId,
};
use iteron_record::Rollout;
use std::{path::Path, time::Instant};

pub(super) struct ToolExecutionJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) ledger: &'a mut Ledger,
    pub(super) failed_actions: &'a mut FailedActionCache,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}

/// A physical ToolDone fact minted only after the actual validated append succeeds. There is no
/// public constructor, deserializer or substitution of a predicted/tail sequence.
pub(crate) struct ToolTerminalReceipt {
    sequence: Seq,
    turn: TurnId,
    tenant: TenantId,
    run: RunId,
    tool: String,
    tool_use_id: String,
    successful: bool,
}
impl ToolTerminalReceipt {
    pub(crate) fn sequence(&self) -> Seq {
        self.sequence
    }
    pub(crate) fn turn(&self) -> TurnId {
        self.turn
    }
    pub(crate) fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub(crate) fn run(&self) -> &RunId {
        &self.run
    }
    pub(crate) fn tool(&self) -> &str {
        &self.tool
    }
    pub(crate) fn tool_use_id(&self) -> &str {
        &self.tool_use_id
    }
    pub(crate) fn successful(&self) -> bool {
        self.successful
    }
}
impl ToolExecutionJournal<'_> {
    pub(super) fn open_tool(
        &mut self,
        workspace: &Path,
        turn: TurnId,
        index: usize,
        call: &ToolUse,
        capability: Capability,
        events: &StreamToolEvents,
    ) -> Result<effects::EffectTicket, KernelError> {
        let effect_id =
            effect_class::effect_id(turn, effect_class::EffectClass::RegistryTool, index);
        events.emit(
            "tool.call_proposed",
            Some(effect_id.clone()),
            LifecyclePayload::default(),
        );
        events.emit(
            "tool.policy_evaluated",
            Some(effect_id),
            LifecyclePayload {
                outcome_code: Some("admitted".into()),
                ..LifecyclePayload::default()
            },
        );
        let ticket = StreamToolJournal {
            rollout: self.rollout,
            effects: self.effects,
            policy: None,
            ledger: self.ledger,
            record_failed: self.record_failed,
            diagnostics: self.diagnostics,
            #[cfg(test)]
            fault: self.fault,
        }
        .open_tool(workspace, turn, index, call, capability)?;
        events.tool_start(call, ticket.effect_id().clone());
        Ok(ticket)
    }
    pub(super) fn settle(
        &mut self,
        ticket: effects::EffectTicket,
        settlement: effects::Settlement,
        cause: UnknownCause,
    ) -> Result<(), KernelError> {
        let started = Instant::now();
        let result = self.effects.settle(self.rollout, ticket, settlement, cause);
        self.measure(started);
        result.map_err(|error| self.boundary_error(error))
    }
    pub(super) fn known_result(
        &mut self,
        ticket: effects::EffectTicket,
        tool: &str,
        result: &ToolResult,
        overlapped_ms: u64,
        events: &StreamToolEvents,
    ) -> Result<(), KernelError> {
        self.record_known_result(ticket, tool, result, overlapped_ms, events)
            .map(|_| ())
    }

    pub(super) fn known_result_receipt(
        &mut self,
        ticket: effects::EffectTicket,
        tool: &str,
        result: &ToolResult,
        overlapped_ms: u64,
        events: &StreamToolEvents,
    ) -> Result<ToolTerminalReceipt, KernelError> {
        let (sequence, turn) =
            self.record_known_result(ticket, tool, result, overlapped_ms, events)?;
        Ok(ToolTerminalReceipt {
            sequence,
            turn,
            tenant: self.rollout.tenant().clone(),
            run: self.rollout.run_id().clone(),
            tool: tool.to_owned(),
            tool_use_id: result.tool_use_id.clone(),
            successful: !result.is_error,
        })
    }

    fn record_known_result(
        &mut self,
        ticket: effects::EffectTicket,
        tool: &str,
        result: &ToolResult,
        overlapped_ms: u64,
        events: &StreamToolEvents,
    ) -> Result<(Seq, TurnId), KernelError> {
        #[cfg(test)]
        self.inject_tool_done_failure()?;
        let effect_id = ticket.effect_id().clone();
        let turn = ticket.turn();
        let started = Instant::now();
        let committed = self.effects.settle_with_sequence(
            self.rollout,
            ticket,
            effects::Settlement::Definite(EventKind::ToolDone {
                result: result.clone(),
                effect_id: Some(effect_id.clone()),
                tool: Some(tool.to_owned()),
            }),
            UnknownCause::Unobserved,
        );
        self.measure(started);
        let sequence = committed.map_err(|error| self.boundary_error(error))?;
        events.emit(
            if result.is_error {
                "tool.call_failed"
            } else {
                "tool.call_completed"
            },
            Some(effect_id.clone()),
            LifecyclePayload {
                duration_us: Some(result.latency_ms.saturating_mul(1_000)),
                ..LifecyclePayload::default()
            },
        );
        events.process_terminal(effect_id, tool, result, true);
        self.ledger
            .tool(result.latency_ms, overlapped_ms, result.is_error);
        Ok((sequence, turn))
    }
    pub(super) fn refused_result(
        &mut self,
        turn: TurnId,
        tool: &str,
        result: &ToolResult,
        reason_code: &'static str,
        events: &StreamToolEvents,
    ) -> Result<(), KernelError> {
        if !result.is_error {
            return Err(KernelError::EffectBoundary(
                "a refused tool cannot publish success without admission".into(),
            ));
        }
        events.emit("tool.call_proposed", None, LifecyclePayload::default());
        #[cfg(test)]
        self.inject_tool_done_failure()?;
        let started = Instant::now();
        let result_append = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::ToolDone {
                result: result.clone(),
                effect_id: None,
                tool: Some(tool.to_owned()),
            },
        });
        self.measure(started);
        result_append.map_err(|error| self.record_error(error))?;
        events.emit(
            "tool.policy_evaluated",
            None,
            LifecyclePayload {
                outcome_code: Some("rejected".into()),
                ..LifecyclePayload::default()
            },
        );
        events.emit(
            "tool.call_failed",
            None,
            LifecyclePayload {
                reason_code: Some(reason_code.into()),
                duration_us: Some(result.latency_ms.saturating_mul(1_000)),
                ..LifecyclePayload::default()
            },
        );
        self.ledger.tool(result.latency_ms, 0, true);
        Ok(())
    }
    #[cfg(test)]
    fn inject_tool_done_failure(&mut self) -> Result<(), KernelError> {
        if *self.fault == Some(DurableAppendFault::ToolDone) {
            *self.fault = None;
            return Err(
                self.record_error(iteron_record::RecordError::Io(std::io::Error::other(
                    "injected durable append failure",
                ))),
            );
        }
        Ok(())
    }
    fn record_error(&mut self, error: iteron_record::RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
    fn boundary_error(&mut self, error: effects::BrokerError) -> KernelError {
        match error {
            effects::BrokerError::Record(error) => self.record_error(error),
            other => KernelError::EffectBoundary(other.to_string()),
        }
    }
    fn measure(&mut self, started: Instant) {
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
    }
}
