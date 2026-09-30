//! Immutable shared frontend/lifecycle projection ports for actual tool admission and settlement.
use super::frontend::FrontendChannelHealth;
use super::frontend_events::{RuntimeFrontendEvent, UiEvent};
use super::lifecycle_hooks::LifecycleHookDispatcher;
use iteron_obs::lifecycle::{LifecycleCorrelation, LifecycleEmitter};
use iteron_protocol::{EffectId, JobId, LifecyclePayload, ToolResult, ToolUse};
use tokio::sync::mpsc::Sender;

/// Tool output count when no textual stream is available.
const NO_TOOL_OUTPUT_BYTES: u64 = 0;

#[derive(Clone)]
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
        self.present(UiEvent::ToolStart {
            id: call.id.clone(),
            name: call.name.clone(),
            args: iteron_record::redact::scrub_value(&call.input),
        });
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
    pub(super) fn projected(&self, visible_bytes: usize) {
        self.emit(
            "context.source.truncated",
            None,
            LifecyclePayload {
                count: Some(1),
                magnitude: Some(u64::try_from(visible_bytes).unwrap_or(u64::MAX)),
                reason_code: Some("tool_result_pressure_projection".into()),
                ..LifecyclePayload::default()
            },
        );
    }
    pub(super) fn present(&self, event: UiEvent) -> bool {
        let before = self.frontend.ui_saturation_count();
        let sent =
            self.frontend
                .try_send_frontend(self.resident_ui.as_ref(), self.ui.as_ref(), event);
        let after = self.frontend.ui_saturation_count();
        if after != before && after.is_power_of_two() {
            self.emit(
                "queue.overflow",
                None,
                LifecyclePayload {
                    count: Some(after),
                    reason_code: Some("runtime_ui".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        sent
    }
    pub(super) fn process_terminal(
        &self,
        effect_id: iteron_protocol::EffectId,
        tool: &str,
        result: &ToolResult,
        definite: bool,
    ) {
        let value = (!result.is_error)
            .then(|| serde_json::from_str::<serde_json::Value>(&result.content).ok())
            .flatten();
        let job_id = value
            .as_ref()
            .and_then(|value| value.get("job_id"))
            .and_then(serde_json::Value::as_str);
        match tool {
            "bash" => {
                if definite
                    && (result.content.starts_with("[exit ")
                        || result.content.contains("[timed out after"))
                {
                    self.emit(
                        "process.spawned",
                        Some(effect_id.clone()),
                        LifecyclePayload::default(),
                    );
                    self.emit(
                        "process.reaped",
                        Some(effect_id),
                        LifecyclePayload {
                            duration_us: Some(result.latency_ms.saturating_mul(1_000)),
                            ..LifecyclePayload::default()
                        },
                    );
                } else if !definite {
                    if result.content.contains("interrupted") {
                        self.emit(
                            "process.kill_sent",
                            Some(effect_id.clone()),
                            LifecyclePayload::default(),
                        );
                    }
                    self.emit(
                        "process.reap_failed",
                        Some(effect_id),
                        LifecyclePayload::default(),
                    );
                }
            }
            "process_start" if definite && !result.is_error => {}
            "process_poll" if definite && !result.is_error => {
                let output_bytes = value
                    .as_ref()
                    .map(|value| {
                        ["stdout", "stderr"]
                            .into_iter()
                            .fold(0u64, |total, stream| {
                                total.saturating_add(
                                    value
                                        .get(stream)
                                        .and_then(|stream| stream.get("text"))
                                        .and_then(serde_json::Value::as_str)
                                        .map(|text| u64::try_from(text.len()).unwrap_or(u64::MAX))
                                        .unwrap_or(iteron_tunables::param_integer("cli.runtime.decision_observability.no_tool_output_bytes",NO_TOOL_OUTPUT_BYTES)),
                                )
                            })
                    })
                    .unwrap_or(iteron_tunables::param_integer("cli.runtime.decision_observability.no_tool_output_bytes",NO_TOOL_OUTPUT_BYTES));
                if output_bytes > 0 {
                    self.process_emit(
                        "tool.output_chunk",
                        effect_id.clone(),
                        job_id,
                        LifecyclePayload {
                            magnitude: Some(output_bytes),
                            ..LifecyclePayload::default()
                        },
                    );
                }
                self.process_emit(
                    "background.attached",
                    effect_id,
                    job_id,
                    LifecyclePayload::default(),
                );
            }
            "process_write" if definite && !result.is_error => self.process_emit(
                "background.input_written",
                effect_id,
                job_id,
                LifecyclePayload {
                    magnitude: value
                        .as_ref()
                        .and_then(|value| value.get("accepted_bytes"))
                        .and_then(serde_json::Value::as_u64),
                    ..LifecyclePayload::default()
                },
            ),
            "process_stop" if definite && !result.is_error => {}
            _ => {}
        }
    }

    fn process_emit(
        &self,
        event: &str,
        effect: EffectId,
        job_id: Option<&str>,
        payload: LifecyclePayload,
    ) {
        let Some(emitter) = &self.lifecycle else {
            return;
        };
        let mut correlation = self.correlation.clone();
        correlation.effect_id = Some(effect);
        correlation.job_id = job_id.map(|id| JobId(id.to_owned()));
        if let Ok(event) = emitter.emit(event, correlation, payload)
            && let Some(dispatcher) = &self.lifecycle_hooks
        {
            dispatcher.dispatch(event);
        }
    }
}
