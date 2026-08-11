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
        UiEvent::Text(t) => app.stream_text(&t),
        UiEvent::Thinking(t) => app.stream_think(&t),
        UiEvent::ToolStart { id, name, args } => app.tool_start(id, name, args),
        UiEvent::ToolEnd {
            id,
            ok,
            exit_code,
            output,
            diff,
        } => app.tool_end(&id, ok, exit_code, output, diff),
        UiEvent::Phase(p) => {
            // Entering the model phase starts the first-token clock; every other phase stops it,
            // because only a model request can be waiting on a provider's first byte (I-64).
            app.awaiting_first_token_since = (p == iteron_protocol::Phase::Model).then(Instant::now);
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
            if let Some(pending) = app.text_scrubber.finish() {
                app.cur_text.push_str(&ui_safe_text(&pending));
                app.cur_text_revision = app.cur_text_revision.wrapping_add(1);
            }
            if let Some(pending) = app.thinking_scrubber.finish() {
                app.cur_think.push_str(&ui_safe_text(&pending));
            }
            app.cost = cost;
            app.last_turn_usage = Some(usage);
            app.last_context = Some(context);
            app.model_context_window = model_context_window;
            app.reserved_output_tokens = Some(reserved_output_tokens);
            app.compaction_trigger_tokens = compaction_trigger_tokens;
            app.effort_application = Some(effort);
            app.turns = app.turns.saturating_add(1);
            app.status = "running…".into();
        }
        UiEvent::Workflow(event) => app.workflow_event(event),
        UiEvent::SteerApplied { count } => {
            for _ in 0..count {
                let _ = app.steer_previews.pop_front();
            }
        }
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
            app.flush_text();
            app.transcript_viewer.close();
            app.status = "approval required".into();
            app.approval_choice = ApprovalChoice::Deny;
            app.pending = Some(Pending {
                id,
                tool,
                cap: capability,
                reason,
                arguments: ui_safe_json(&arguments),
                workspace: ui_safe_text(&workspace),
            });
        }
        UiEvent::Done(o) => {
            app.flush_text(); // finalize any in-flight answer/reasoning into blocks
            let _ = o; // the reclaimed run publishes the human outcome in the active shelf
        }
    }
}
