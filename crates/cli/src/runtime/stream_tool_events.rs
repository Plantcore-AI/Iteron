//! Immutable frontend/lifecycle projection ports for actual streamed admission.
use super::frontend::FrontendChannelHealth;
use super::frontend_events::{RuntimeFrontendEvent, UiEvent};
use super::lifecycle_hooks::LifecycleHookDispatcher;
use iteron_obs::lifecycle::{LifecycleCorrelation, LifecycleEmitter};
use iteron_protocol::{EffectId, LifecyclePayload, ToolUse};
use tokio::sync::mpsc::Sender;

pub(super) struct StreamToolEvents {
    pub(super) frontend: FrontendChannelHealth,
    pub(super) ui: Option<Sender<UiEvent>>,
    pub(super) resident_ui: Option<Sender<RuntimeFrontendEvent>>,
    pub(super) lifecycle: Option<LifecycleEmitter>,
    pub(super) lifecycle_hooks: Option<LifecycleHookDispatcher>,
    pub(super) correlation: LifecycleCorrelation,
}
impl StreamToolEvents {
    pub(super) fn declared(&self, call: &ToolUse) {
        let _ = self.frontend.try_send_frontend(
            self.resident_ui.as_ref(),
            self.ui.as_ref(),
            UiEvent::ToolStart {
                id: call.id.clone(),
                name: call.name.clone(),
                args: iteron_record::redact::scrub_value(&call.input),
            },
        );
    }
    pub(super) fn emit(&self, event: &str, effect: Option<EffectId>, payload: LifecyclePayload) {
        let Some(emitter) = &self.lifecycle else {
            return;
        };
        let mut correlation = self.correlation.clone();
        correlation.effect_id = effect;
        if let Ok(event) = emitter.emit(event, correlation, payload)
            && let Some(dispatcher) = &self.lifecycle_hooks
        {
            dispatcher.dispatch(event);
        }
    }
    pub(super) fn tool_start(&self, call: &ToolUse, effect: EffectId) {
        for event in ["tool.call_admitted", "tool.call_started"] {
            self.emit(event, Some(effect.clone()), LifecyclePayload::default());
        }
        if matches!(call.name.as_str(), "bash" | "process_start") {
            self.emit(
                "process.spawn_requested",
                Some(effect),
                LifecyclePayload::default(),
            );
        }
    }
}
