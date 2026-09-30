//! Single checkpoint state and physical publication coordinator. A tree is published to live
//! recovery state only after its actual Checkpoint event and effect terminal are committed.

#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::effect_descriptor::{
    effect_class_label, effect_done_terminal, effect_failed_terminal, effect_workspace,
};
use super::effect_journal_owner::{EffectJournalOwner, UnknownCause};
use super::lifecycle_hooks::LifecycleHookDispatcher;
use super::turn_activity::{ActivitySink, ActivityStage};
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_kernel::{effect_class, effects};
use iteron_obs::{
    Ledger,
    lifecycle::{LifecycleCorrelation, LifecycleEmitter},
};
use iteron_protocol::{
    ActivityDetailCode, Capability, Event, EventKind, LifecyclePayload, Seq, TurnId,
};
use iteron_record::{RecordError, Rollout, Snapshot};
use std::{path::Path, time::Instant};

#[derive(Default)]
pub(super) struct WorkspaceCheckpointOwner {
    latest: Option<Snapshot>,
    last_turn: Option<TurnId>,
}
impl WorkspaceCheckpointOwner {
    pub(super) fn latest(&self) -> Option<&Snapshot> {
        self.latest.as_ref()
    }
    pub(super) fn interval_elapsed(&self, turn: TurnId, minimum: u32) -> bool {
        self.last_turn
            .is_none_or(|previous| turn.0.saturating_sub(previous.0) >= minimum)
    }
}

pub(super) struct CheckpointScope<'a> {
    pub(super) turn: TurnId,
    pub(super) workspace: &'a Path,
    pub(super) runtime_state: &'a Path,
    pub(super) activity: ActivitySink,
    pub(super) lifecycle: Option<LifecycleEmitter>,
    pub(super) hooks: Option<LifecycleHookDispatcher>,
    pub(super) correlation: LifecycleCorrelation,
}

pub(super) struct WorkspaceCheckpoint<'a> {
    pub(super) owner: &'a mut WorkspaceCheckpointOwner,
    pub(super) rollout: &'a mut Rollout,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
    pub(super) scope: CheckpointScope<'a>,
}

impl WorkspaceCheckpoint<'_> {
    pub(super) fn create(mut self, required: bool) -> Result<(), KernelError> {
        if !iteron_record::checkpoint_supported(self.scope.workspace) {
            return if required {
                Err(RecordError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "workspace is not a git work tree; checkpoint requires one",
                ))
                .into())
            } else {
                Ok(())
            };
        }
        if self.scope.runtime_state.as_os_str().is_empty() {
            return Err(RecordError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rollout has no runtime-state directory",
            ))
            .into());
        }
        let physical_path = self
            .rollout
            .path()
            .canonicalize()
            .map_err(RecordError::Io)?;
        if !physical_path.starts_with(self.scope.runtime_state) {
            return Err(RecordError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "active rollout is outside the invariant runtime-state directory",
            ))
            .into());
        }
        let turn = self.scope.turn;
        let class = effect_class::EffectClass::Checkpoint;
        let ordinal = self.effects.next_ordinal(turn, class);
        self.emit("checkpoint.requested");
        let activity = self
            .scope
            .activity
            .span(ActivityStage::Checkpoint, Some(turn));
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::EffectIntent) {
            *self.fault = None;
            activity.fail(ActivityDetailCode::Checkpoint);
            return Err(self.record_error(RecordError::Io(std::io::Error::other(
                "injected durable effect-intent append failure",
            ))));
        }
        let started = Instant::now();
        let opened = self.effects.open(
            self.rollout,
            effects::BrokeredEffect {
                turn,
                effect_id: effect_class::effect_id(turn, class, ordinal),
                tool_use_id: effect_class::harness_correlation_id(turn, class, ordinal),
                kind: effect_class_label(class).into(),
                capability: Capability::ReversibleLocal,
                audit_arguments: serde_json::json!({"scope":"workspace-excluding-runtime-state"}),
                workspace: effect_workspace(self.scope.workspace),
                provider_route_attempt: None,
            },
        );
        self.measure(started);
        let ticket = opened.map_err(|error| self.boundary_error(error))?;
        let at = self.rollout.next_sequence();
        let snapshot = match iteron_record::checkpoint_excluding_runtime_state(
            self.rollout.run_id(),
            at,
            self.scope.workspace,
            self.scope.runtime_state,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.settle(
                    ticket,
                    effects::Settlement::Definite(effect_failed_terminal(
                        turn,
                        class,
                        ordinal,
                        &error.to_string(),
                    )),
                )?;
                self.emit("checkpoint.failed");
                activity.fail(ActivityDetailCode::Checkpoint);
                return Err(error.into());
            }
        };
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::Checkpoint) {
            *self.fault = None;
            activity.fail(ActivityDetailCode::Checkpoint);
            return Err(self.record_error(RecordError::Io(std::io::Error::other(
                "injected durable checkpoint publication refusal",
            ))));
        }
        let started = Instant::now();
        let appended = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::Checkpoint {
                at: snapshot.at,
                tree_ref: snapshot.tree_ref.clone(),
            },
        });
        self.measure(started);
        let source = appended.map_err(|error| self.record_error(error))?;
        if source != snapshot.at {
            return Err(self.record_error(RecordError::InvalidAppendBatch {
                reason: "checkpoint publication sequence differs from its physical snapshot",
            }));
        }
        self.settle(
            ticket,
            effects::Settlement::Definite(effect_done_terminal(turn, class, ordinal)),
        )?;
        // Neither a completed filesystem copy nor an unconfirmed journal append can replace the
        // live rollback point. The known terminal receipt is the final publication barrier.
        self.owner.latest = Some(snapshot);
        self.owner.last_turn = Some(turn);
        self.emit("checkpoint.created");
        activity.complete();
        Ok(())
    }

    fn settle(
        &mut self,
        ticket: effects::EffectTicket,
        settlement: effects::Settlement,
    ) -> Result<(), KernelError> {
        let started = Instant::now();
        let result =
            self.effects
                .settle(self.rollout, ticket, settlement, UnknownCause::Unobserved);
        self.measure(started);
        result.map_err(|error| self.boundary_error(error))
    }
    fn measure(&mut self, started: Instant) {
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
    }
    fn record_error(&mut self, error: RecordError) -> KernelError {
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
    fn emit(&self, id: &'static str) {
        if let Some(emitter) = &self.scope.lifecycle
            && let Ok(event) = emitter.emit(
                id,
                self.scope.correlation.clone(),
                LifecyclePayload::default(),
            )
            && let Some(hooks) = &self.scope.hooks
        {
            hooks.dispatch(event);
        }
    }
}
