use super::*;

/// Apply one EQ envelope.
///
/// The frontend's whole view of the runtime arrives through here. `RunEnded` carries what the
/// `handle.await` reclaim used to read straight off the `Agent`; there is no join any more, so the
/// terminal event is also the refresh point.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_server_event<T: notification::NotificationTransport + ?Sized>(
    app: &mut App,
    session: &mut Session,
    event: app_server::ServerEvent,
    notifier: &mut notification::TerminalNotifier,
    writer: &mut T,
    interrupt: &Arc<AtomicBool>,
    drain: &Arc<AtomicBool>,
) {
    match event {
        app_server::ServerEvent::Ui(event) => apply_live_event(app, event, notifier, writer),
        app_server::ServerEvent::WorkflowRun(event) => app.workflow_run_ui_event(event),
        app_server::ServerEvent::Notice(text) => app.note(block::NoticeLevel::Warn, text),
        app_server::ServerEvent::Submission {
            id,
            state,
            reason_code,
        } => {
            if state == iteron_protocol::SubmissionLifecycleState::Received
                && let Some(pending) = app.pending_turn_receipt.as_ref()
                && pending.id == id
                && pending.clear_composer
            {
                if app.editor.persistence_revision() == pending.editor_revision {
                    let _ = app.editor.take_submit();
                } else {
                    app.note(
                        block::NoticeLevel::Info,
                        "submission received; composer changed before its receipt, so the newer draft was preserved",
                    );
                }
            }
            if state == iteron_protocol::SubmissionLifecycleState::Applied
                && app
                    .pending_turn_receipt
                    .as_ref()
                    .is_some_and(|pending| pending.id == id)
                && let Some(pending) = app.pending_turn_receipt.take()
            {
                app.push_user(pending.display_text);
            }
            if matches!(
                state,
                iteron_protocol::SubmissionLifecycleState::Rejected
                    | iteron_protocol::SubmissionLifecycleState::Expired
            ) {
                if app
                    .pending_turn_receipt
                    .as_ref()
                    .is_some_and(|pending| pending.id == id)
                {
                    app.pending_turn_receipt = None;
                    app.running = false;
                    app.interrupting = false;
                    app.force_cancelling = false;
                    app.draining = false;
                }
                app.note(
                    block::NoticeLevel::Warn,
                    format!(
                        "submission {} {}{}",
                        id.0,
                        match state {
                            iteron_protocol::SubmissionLifecycleState::Rejected => "rejected",
                            _ => "expired",
                        },
                        reason_code
                            .map(|reason| format!(" · {reason}"))
                            .unwrap_or_default()
                    ),
                );
            }
        }
        app_server::ServerEvent::Lagged { dropped } => app.note(
            block::NoticeLevel::Warn,
            format!(
                "{dropped} streamed update(s) were dropped to keep the event queue bounded; the \
                 transcript above is incomplete at that point"
            ),
        ),
        app_server::ServerEvent::RunEnded { snapshot, summary } => {
            let completion_notification = notifier.run_completed();
            app.running = false;
            app.interrupting = false;
            app.force_cancelling = false;
            app.draining = false;
            app.run_started = None;
            app.awaiting_first_token_since = None;
            app.flush_text();
            app.pending = None; // a pending approval cannot outlive its run
            app.settle_unfinished_tools();
            interrupt.store(false, Ordering::Relaxed);
            drain.store(false, Ordering::Relaxed);

            // A channel send is not delivery. The exact raw texts the kernel did not admit come
            // back on the snapshot and go into the frontend's own submission order, so nothing is
            // lost, duplicated, or reordered across the turn boundary.
            let (count, unmatched_previews) =
                app.requeue_unadmitted(snapshot.unadmitted_steers.clone());
            if count > 0 {
                app.note(
                    block::NoticeLevel::Warn,
                    format!(
                        "{count} steering submission(s) missed the safe point; queued after the turn"
                    ),
                );
            }
            if unmatched_previews > 0 {
                app.note(
                    block::NoticeLevel::Warn,
                    format!(
                        "delivery could not be confirmed for {unmatched_previews} steering submission(s); preserved after the turn"
                    ),
                );
            }

            app.mode = snapshot.mode;
            app.effort = snapshot.effort;
            app.model = snapshot.model.clone();
            app.cost = snapshot.cost.clone();
            app.last_turn_usage = snapshot.last_turn_usage;
            session.adopt(*snapshot);
            app.session_name = session_display_name(session.rollout_path());

            let result = summary.result_v5();
            let canonical_outcome = result
                .get("outcome")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("harness_error");
            if let Some(detail) = result
                .get("error")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            {
                // Everything already streamed is on the record as an interrupted message, so a
                // retry continues from evidence rather than from nothing (I-39).
                let detail = if app.retryable_task.is_some() {
                    format!("{detail}\n\n{RETRY_HINT}")
                } else {
                    detail
                };
                app.push_block(block::BlockKind::Error {
                    title: "run failed".into(),
                    detail,
                    open: true,
                });
            } else {
                // The turn landed; there is nothing to re-send.
                app.retryable_task = None;
            }
            // A budget stop is not a failure and gets no error block, so without this the operator
            // saw only `idle · last: budget_exhausted` — true, and silent about the fact that the
            // turn ceiling is raisable in place.
            if canonical_outcome == "budget_exhausted" {
                let reason = result
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                app.note(
                    block::NoticeLevel::Warn,
                    format!(
                        "stopped on the {reason} ceiling — {}",
                        crate::output::budget_remedy(reason)
                    ),
                );
            }
            app.status = format!("idle · last: {canonical_outcome}");
            app.last_result = Some(result);
            if let Some(trigger) = completion_notification {
                notifier.emit_transport(writer, trigger);
            }
        }
    }
}

pub(super) async fn apply_workflows_panel_action(
    app: &mut App,
    session: &mut Session,
    action: workflows_panel::Action,
) {
    let control = match action {
        workflows_panel::Action::Cancel(run_id) => {
            app.workflows_panel
                .begin_action(format!("stopping {run_id}"));
            app_server::WorkflowControl::Cancel { run_id }
        }
        workflows_panel::Action::Resume(run_id) => {
            app.workflows_panel
                .begin_action(format!("resuming {run_id}"));
            app_server::WorkflowControl::Resume { run_id }
        }
        workflows_panel::Action::NewPrompt => {
            app.status = "ready · compose a new prompt".into();
            return;
        }
    };
    match session
        .control(app_server::Control::Workflow(control))
        .await
    {
        Some(app_server::ControlReply::Workflows(reply)) => {
            app.workflows_panel.update_inventory(reply.runs);
            app.workflows_panel.finish_action(
                reply
                    .notice
                    .unwrap_or_else(|| "workflow owner state refreshed".into()),
            );
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.workflows_panel.finish_action(reason)
        }
        _ => app
            .workflows_panel
            .finish_action("the workflow owner is no longer reachable"),
    }
}

/// Instantiate and validate the new `(provider, model)` pair before mutating either field. A
/// failed construction leaves the old provider and old model together, avoiding cross-provider
/// requests with a model id from a different account.
pub(super) async fn apply_model_selection(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    selection: ModelSelection,
) {
    let provider = match directory.build(&selection) {
        Ok(provider) => provider,
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!("cannot switch model: {error}"),
            );
            return;
        }
    };

    let changed =
        session.model() != selection.model_id || app.route.provider_id != selection.provider_id;
    let provider_name = directory
        .entry(&selection.provider_id)
        .map(|entry| entry.display_name().to_owned())
        .unwrap_or_else(|| selection.provider_id.clone());

    // One transaction, applied by the runtime. The write-ahead audit, the capability fields and the
    // rate-card rebind used to be four separate statements here, each able to fail after the
    // previous one had already taken effect; the server now applies them in the kernel's required
    // order and answers with the state it actually reached.
    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let capabilities = directory.selection_capabilities(&selection);
    let reply = session
        .control(app_server::Control::SelectModel(Box::new(
            app_server::ModelSelection {
                provider,
                provider_id: selection.provider_id.clone(),
                model_id: selection.model_id.clone(),
                catalog_digest,
                capability_digest,
                context_window_tokens: capabilities.context_window_tokens,
                max_output_tokens: capabilities.max_output_tokens,
            },
        )))
        .await;
    let state = match reply {
        Some(app_server::ControlReply::State(state)) => state,
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason);
            return;
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the runtime is no longer reachable",
            );
            return;
        }
    };

    app.model = state.model.clone();
    // Re-derive the ONE route view from the directory, so the statusline, /status and /config all
    // move together with the request the next turn dispatches. The model comes from the state the
    // runtime actually reached, not from what was requested of it.
    let applied = ModelSelection {
        provider_id: selection.provider_id.clone(),
        model_id: state.model.clone(),
    };
    app.route = app.route.reselect(directory, &applied);
    app.model_context_window = capabilities.context_window_tokens;
    // A model chosen in the TUI is an operator decision, and until now it evaporated at exit:
    // nothing in the product ever wrote the user config (I-25). Persist it through the same single
    // atomic writer `core config set` uses, so the next launch starts on the route the operator
    // picked (I-26). Provider and model go in ONE transaction: persisting the model alone would
    // leave the next launch pairing a new model with the previous provider.
    let persisted_provider = applied.provider_id.clone();
    let persisted_model = applied.model_id.clone();
    match crate::config::update_user_config(move |config| {
        crate::config::apply_setting(config, "provider", &persisted_provider)?;
        crate::config::apply_setting(config, "model", &persisted_model)
    }) {
        Ok(_) => {}
        Err(error) => app.note(
            block::NoticeLevel::Warn,
            format!("route applied for this session but not persisted: {error}"),
        ),
    }
    if changed {
        clear_last_turn_telemetry_from(app, &state);
    }
    app.note(
        block::NoticeLevel::Ok,
        format!(
            "model set to {}:{}  ·  {provider_name} backend",
            selection.provider_id, selection.model_id
        ),
    );
    if changed {
        app.note(
            block::NoticeLevel::Warn,
            "switching model re-reads the history uncached (new prefix cache)",
        );
    }
}

/// Clear the per-request telemetry after a route or effort change, from a server snapshot.
///
/// The ledger half of the old function reached into `agent.ledger` to reset it; the resident runtime
/// does that on its own side when it applies the transition, so the frontend only has to stop
/// displaying values that no longer describe anything.
pub(super) fn clear_last_turn_telemetry_from(app: &mut App, state: &app_server::SessionSnapshot) {
    app.last_turn_usage = state.last_turn_usage;
    app.last_context = None;
    app.reserved_output_tokens = None;
    app.effort_application = None;
}

/// Resolve an explicit model-leaf retry without weakening normal selection. A qualified value is
/// treated as `provider:model` only when the prefix names a configured provider, preserving model
/// ids such as OpenAI fine-tunes that themselves contain colons.
pub(super) fn model_retry_selection(
    directory: &ProviderDirectory,
    current_provider: &str,
    current_model: &str,
    value: &str,
) -> Result<ModelSelection, String> {
    let value = value.trim();
    if value.is_empty() {
        if current_provider.is_empty() || current_model.is_empty() {
            return Err("no current provider/model is available to retry".into());
        }
        return Ok(ModelSelection {
            provider_id: current_provider.to_owned(),
            model_id: current_model.to_owned(),
        });
    }
    if let Some((provider_id, model_id)) = value
        .split_once(':')
        .filter(|(provider_id, _)| directory.entry(provider_id).is_some())
    {
        if model_id.is_empty() {
            return Err("retry target must include a model id".into());
        }
        return Ok(ModelSelection {
            provider_id: provider_id.to_owned(),
            model_id: model_id.to_owned(),
        });
    }
    if current_provider.is_empty() {
        return Err("retry a non-current provider with provider:model-id".into());
    }
    Ok(ModelSelection {
        provider_id: current_provider.to_owned(),
        model_id: value.to_owned(),
    })
}

/// Commit one runtime setting through the kernel's durable policy transaction. Frontend mirrors
/// change only after the record append + fsync succeeds, so a visible control can never claim a
/// state that resume/fork would lose.
pub(super) async fn commit_effort(app: &mut App, session: &mut Session, next: Effort) -> bool {
    // A control round trip, not a method call on an `Agent` the frontend happens to hold. The
    // answer is the state the runtime actually reached: `app.effort` is set from the reply, so a
    // refusal leaves the display showing what is true rather than what was asked for.
    match session.control(app_server::Control::SetEffort(next)).await {
        Some(app_server::ControlReply::State(state)) => {
            app.effort = state.effort;
            clear_last_turn_telemetry_from(app, &state);
            true
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(
                block::NoticeLevel::Err,
                format!("effort was not changed: {reason}"),
            );
            false
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the runtime is no longer reachable",
            );
            false
        }
    }
}

pub(super) async fn commit_permission_mode(
    app: &mut App,
    session: &mut Session,
    next: PermissionMode,
) -> bool {
    match session
        .control(app_server::Control::SetPermissionMode(next))
        .await
    {
        Some(app_server::ControlReply::State(state)) => {
            app.mode = state.mode;
            true
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(
                block::NoticeLevel::Err,
                format!("permission mode was not changed: {reason}"),
            );
            false
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the runtime is no longer reachable",
            );
            false
        }
    }
}

pub(super) async fn commit_permission_capability(
    app: &mut App,
    session: &mut Session,
    capability: Capability,
    verdict: Verdict,
) -> bool {
    match session
        .control(app_server::Control::SetCapabilityRule {
            capability,
            verdict,
        })
        .await
    {
        Some(app_server::ControlReply::State(state)) => {
            app.mode = state.mode;
            true
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(
                block::NoticeLevel::Err,
                format!("the permission rule was not changed: {reason}"),
            );
            false
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the runtime is no longer reachable",
            );
            false
        }
    }
}

/// Apply a picked action to the idle agent + UI state (C5 take-then-apply calls this after dropping
/// the picker borrow). Surfaces a Notice if the agent is gone rather than silently no-op'ing (C6).
pub(super) async fn apply_action(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    action: PickAction,
) {
    match action {
        PickAction::AdoptRun(run_id) => adopt_session(app, session, directory, &run_id).await,
        PickAction::InspectTunable(detail) => show_tunable_detail(app, detail),
        PickAction::Info => {}
        PickAction::SetModel(selection) => {
            apply_model_selection(app, session, directory, selection).await
        }
        PickAction::SetEffort(e) => {
            if commit_effort(app, session, e).await {
                let lvl = if e == Effort::Ultracode {
                    block::NoticeLevel::Warn
                } else {
                    block::NoticeLevel::Ok
                };
                app.note(lvl, format!("effort set to {} — {}", e.label(), e.hint()));
            }
        }
        PickAction::SetMode(m) => {
            if commit_permission_mode(app, session, m).await {
                app.note(block::NoticeLevel::Ok, format!("mode set to {}", m.label()));
            }
        }
        PickAction::SetCap(c, v) => {
            let vl = match v {
                Verdict::Auto => "allow",
                Verdict::Ask => "ask",
                Verdict::Deny => "deny",
            };
            if commit_permission_capability(app, session, c, v).await {
                app.note(
                    block::NoticeLevel::Ok,
                    format!("permission rule: {} → {vl}", cap_label(c)),
                );
            }
        }
        PickAction::SetTheme(theme) => apply_theme_selection(app, theme),
    }
}

pub(super) fn show_tunable_detail(app: &mut App, detail: tunables_view::Detail) {
    let (family_id, detail_rows, notes) = detail.into_panel();
    let mut rows: Vec<block::PanelRow> = detail_rows
        .into_iter()
        .map(|(key, value)| kv(&key, &value))
        .collect();
    rows.extend(notes.into_iter().map(block::PanelRow::Note));
    app.panel("", &format!("tunable · {family_id}"), rows);
}

pub(super) fn apply_theme_selection(app: &mut App, theme: theme::Theme) {
    // Navigation live-previews, while immediate Enter on the first row applies it here.
    app.set_theme(theme);
    app.note(block::NoticeLevel::Ok, "theme applied");
}
