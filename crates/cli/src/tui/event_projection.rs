use super::*;

/// Project one live event into retained UI state, then send any fixed terminal notification
/// directly through the backend. Keeping the writer outside `App` makes it impossible for an OSC
/// payload to enter transcript blocks or ratatui's frame buffer.
pub(super) fn apply_live_event<T: notification::NotificationTransport + ?Sized>(
    app: &mut App,
    ev: UiEvent,
    notifier: &mut notification::TerminalNotifier,
    writer: &mut T,
) {
    let trigger = notifier.trigger_for_event(&ev);
    apply_event(app, ev);
    if let Some(trigger) = trigger {
        notifier.emit_transport(writer, trigger);
    }
}

pub(super) fn apply_event(app: &mut App, ev: UiEvent) {
    match ev {
        UiEvent::Text(t) => {
            if !app.product.stream_active() {
                app.stream_text(&t);
            }
        }
        UiEvent::Thinking(t) => {
            if !app.product.stream_active() {
                app.stream_think(&t);
            }
        }
        UiEvent::ToolStart { id, name, args } => app.tool_start(id, name, args),
        UiEvent::ToolEnd {
            id,
            ok,
            exit_code,
            output,
            diff,
        } => app.tool_end(&id, ok, exit_code, output, diff),
        UiEvent::Phase(p) => {
            // Durable Phase is not transport authority. Local request assembly and admission also
            // happen under Model, so TTFT begins only when the RequestSent activity arrives.
            app.activity_observations.finish_provider_wait();
            if p == iteron_protocol::Phase::Model {
                app.assistant.begin_model_turn();
            }
            app.status = p.label().into();
        }
        UiEvent::TurnEnd {
            cost,
            usage,
            context,
            model_context_window,
            reserved_output_tokens,
            compaction_trigger_tokens,
            effort,
        } => {
            // A provider turn is a semantic token boundary. Release the last held word only after
            // scrubbing the complete token; keep it in the live block until Done/tool framing.
            app.assistant.finish_boundaries();
            app.telemetry
                .observe_provider_turn(super::session_telemetry::ProviderTurnTelemetry {
                    cost,
                    usage,
                    context,
                    model_context_window,
                    reserved_output_tokens,
                    compaction_trigger_tokens,
                    effort,
                });
            app.status = "provider turn complete · continuing…".into();
        }
        UiEvent::Workflow(event) => app.workflow_event(event),
        // Legacy count events lack an ID and cannot settle an identified TUI preview.
        UiEvent::SteerApplied { .. } => {}
        UiEvent::SteerSubmissionApplied { id } => app.settle_steer_submission(id),
        // The submission receipt is projected by App Server; an unconfirmed TUI steer preview
        // stays until turn-end recovery can preserve its text as a follow-up.
        UiEvent::SubmissionRejected { .. } | UiEvent::ControlSubmissionApplied { .. } => {}
        UiEvent::Notice(n) => {
            app.push_block(block::BlockKind::Notice {
                level: block::NoticeLevel::Info,
                text: n,
            });
        }
        UiEvent::ApprovalRequest {
            id,
            tool,
            capability,
            reason,
            arguments,
            workspace,
        } => {
            if app.product.stream_active() {
                return;
            }
            app.flush_text();
            app.transcript_viewer.close();
            app.status = "approval required".into();
            app.permission_prompt.present(Pending {
                id,
                tool,
                cap: capability,
                reason,
                arguments: ui_safe_json(&arguments),
                workspace: ui_safe_text(&workspace),
                prompt_complete: true,
            });
        }
        UiEvent::ApprovalResolved {
            id,
            resolution,
            reason_code,
            ..
        } => {
            if app.permission_prompt.resolve(id) {
                let decision = match resolution {
                    crate::runtime::ApprovalResolution::Approved => "approved · tool pending",
                    crate::runtime::ApprovalResolution::Denied => "denied",
                    crate::runtime::ApprovalResolution::Cancelled => "cancelled",
                    crate::runtime::ApprovalResolution::TimedOut => "timed out",
                };
                app.status = format!("approval {decision} · {}", ui_safe_text(reason_code));
            }
        }
        UiEvent::Done(o) => {
            app.flush_text(); // finalize any in-flight answer/reasoning into blocks
            app.status = "finalizing · recording outcome…".into();
            let _ = o; // the reclaimed run publishes the human outcome in the active shelf
        }
    }
}
