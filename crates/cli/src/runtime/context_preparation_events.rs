//! Frozen context lifecycle projection. Turn correlation comes from actual control/physical
//! boundaries; this observational port grants no hook, provider or transcript authority.
use super::lifecycle_hooks::LifecycleHookDispatcher;
use iteron_obs::lifecycle::{LifecycleCorrelation, LifecycleEmitter};
use iteron_protocol::{LifecyclePayload, TurnId};

pub(super) struct ContextPreparationEvents {
    pub(super) lifecycle: Option<LifecycleEmitter>,
    pub(super) hooks: Option<LifecycleHookDispatcher>,
    pub(super) correlation: LifecycleCorrelation,
}

impl ContextPreparationEvents {
    pub(super) fn emit(&self, turn: TurnId, id: &str, payload: LifecyclePayload) {
        self.emit_optional(id, Some(turn), payload);
    }

    pub(super) fn emit_optional(&self, id: &str, turn: Option<TurnId>, payload: LifecyclePayload) {
        let Some(emitter) = &self.lifecycle else {
            return;
        };
        let mut correlation = self.correlation.clone();
        correlation.turn_id = turn;
        if let Ok(event) = emitter.emit(id, correlation, payload)
            && let Some(hooks) = &self.hooks
        {
            hooks.dispatch(event);
        }
    }
}
