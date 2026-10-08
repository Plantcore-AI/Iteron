//! Existing context and optional memory gates through their actual executable hook owner.
//! This finite owner consumes each protected source once; a dropped gate cannot be rearmed.
use super::KernelError;
use super::context_preparation_events::ContextPreparationEvents;
use super::hook_execution::HookExecution;
use super::hooks::HookDecision;
use iteron_obs::{Ledger, PhaseSpan};
use iteron_protocol::{LifecyclePayload, Phase, TurnId};

pub(super) struct ContextInjectionGate<'a> {
    pub(super) hooks: HookExecution<'a>,
    pub(super) events: ContextPreparationEvents,
}

pub(super) struct ContextInjectionTiming(PhaseSpan);

impl ContextInjectionGate<'_> {
    pub(super) async fn run(
        mut self,
        turn: TurnId,
        task_bytes: usize,
        memory: bool,
    ) -> Result<ContextInjectionTiming, KernelError> {
        let span = PhaseSpan::enter(Phase::Context);
        let magnitude = Some(u64::try_from(task_bytes).unwrap_or(u64::MAX));
        let gates = [
            ("context.source.discovered", magnitude),
            ("memory.query.created", magnitude),
            ("memory.budget.requested", None),
        ];
        for (event, magnitude) in gates.into_iter().take(if memory { 3 } else { 1 }) {
            self.events.emit(
                turn,
                event,
                LifecyclePayload {
                    magnitude,
                    ..LifecyclePayload::default()
                },
            );
            let report = self.hooks.lifecycle(event).await?;
            if let HookDecision::Deny(reason) = report.decision {
                return Err(KernelError::ContextResolution(reason));
            }
        }
        Ok(ContextInjectionTiming(span))
    }
}

impl ContextInjectionTiming {
    pub(super) fn finish(self, ledger: &mut Ledger) {
        ledger.phase_context(self.0.elapsed_ms());
    }
}
