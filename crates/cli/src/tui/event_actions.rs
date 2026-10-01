use super::*;

/// Apply one EQ envelope.
///
/// The frontend's whole view of the runtime arrives through here. `RunEnded` carries what the
/// `handle.await` reclaim used to read straight off the `Agent`; there is no join any more, so the
/// terminal event is also the refresh point.
///
/// `directory` is the resolver `RunEnded` needs to re-render the route the runtime actually ended
/// on. It is optional only so a caller with no directory in hand (tests, and any frontend that
/// never rebinds a route) stays source-compatible; `None` keeps the previously resolved route
/// rather than resolving a blocked one.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_server_event<T: notification::NotificationTransport + ?Sized>(
    app: &mut App,
    session: &mut Session,
    event: app_server::ServerEvent,
    notifier: &mut notification::TerminalNotifier,
    writer: &mut T,
    interrupt: &Arc<AtomicBool>,
    drain: &Arc<AtomicBool>,
    directory: Option<&ProviderDirectory>,
) {
    match event {
        app_server::ServerEvent::Ui(event) => apply_live_event(app, event, notifier, writer),
        app_server::ServerEvent::Plantcore(_) => {}
        app_server::ServerEvent::AdvisoryMaintenance(event) => {
            super::advisory_maintenance::apply(app, session, event)
        }
        app_server::ServerEvent::MaintenanceAvailability(event) => {
            super::advisory_maintenance::availability(app, session, event)
        }
        app_server::ServerEvent::TurnPublication(event) => {
            super::turn_publication::apply(app, session, event)
        }
        app_server::ServerEvent::WorkflowRun(event) => app.workflow_run_ui_event(event),
        app_server::ServerEvent::Activity(event) => {
            match app.activity_observations.observe(event, app.run.running()) {
                super::activity_presentation::ActivityReaction::None => {}
                super::activity_presentation::ActivityReaction::Status(status) => {
                    app.status = status.into()
                }
                super::activity_presentation::ActivityReaction::Invalid => app.note(
                    block::NoticeLevel::Err,
                    "runtime emitted an invalid bounded activity event; it was not rendered",
                ),
                super::activity_presentation::ActivityReaction::Saturated => app.note(
                    block::NoticeLevel::Warn,
                    "activity display is incomplete; /activity reads the actual owners",
                ),
            }
        }
        app_server::ServerEvent::Notice(text) => app.note(block::NoticeLevel::Warn, text),
        app_server::ServerEvent::McpInputRequested(prompt) => {
            if let Err(prompt) = app.enqueue_mcp_input(prompt) {
                let _ = session.answer_mcp_input(app_server::McpInputResponse {
                    request_id: prompt.request_id,
                    answer: app_server::McpInputAnswer::Reject,
                });
                app.note(
                    block::NoticeLevel::Warn,
                    "too many pending MCP input requests; the newest request was declined",
                );
            }
        }
        app_server::ServerEvent::Submission {
            id,
            state,
            reason_code,
        } => {
            match app.run.observe_receipt(id, state) {
                super::run_presentation::ReceiptObservation::Received {
                    editor_revision,
                    clear_composer: true,
                } => {
                    if app.editor.persistence_revision() == editor_revision {
                        let _ = app.editor.take_submit();
                    } else {
                        app.note(block::NoticeLevel::Info, "submission received; composer changed before its receipt, so the newer draft was preserved");
                    }
                }
                super::run_presentation::ReceiptObservation::Applied { display_text } => {
                    app.push_user(display_text)
                }
                super::run_presentation::ReceiptObservation::Refused => {
                    app.activity_observations.retire_run_observations()
                }
                super::run_presentation::ReceiptObservation::Received {
                    clear_composer: false,
                    ..
                }
                | super::run_presentation::ReceiptObservation::None => {}
            }
            if matches!(
                state,
                iteron_protocol::SubmissionLifecycleState::Rejected
                    | iteron_protocol::SubmissionLifecycleState::Expired
            ) {
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
            app.run.run_ended(Instant::now());
            app.ctrl_c_quit_deadline = None;
            app.activity_observations.retire_run_observations();
            app.flush_think();
            app.finish_text_boundary();
            let terminal_answer = app
                .product
                .take_terminal()
                .unwrap_or_else(|| iteron_record::redact::scrub(&summary.assistant_text));
            if app.reconcile_terminal_assistant(&terminal_answer) {
                app.note(
                    block::NoticeLevel::Warn,
                    "terminal authority exposed a middle-gap, duplicate, or rewrite ambiguity; the current response was rebuilt exactly from the terminal answer",
                );
            }
            app.flush_text();
            app.permission_prompt.clear(); // only the actual run terminal clears its prompt
            app.clear_mcp_inputs();
            app.settle_unfinished_tools();
            interrupt.store(false, Ordering::Relaxed);
            drain.store(false, Ordering::Relaxed);

            // A channel send is not delivery. The exact raw texts the kernel did not admit come
            // back on the snapshot and go into the frontend's own submission order, so nothing is
            // lost, duplicated, or reordered across the turn boundary.
            let (count, unmatched_previews) = app.requeue_unadmitted(
                snapshot.unadmitted_steers.clone(),
                &snapshot.unadmitted_steer_submission_ids,
            );
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

            let route_changed = snapshot.provider_id != session.state.provider_id
                || snapshot.model != session.state.model;
            let effort_changed = snapshot.effort != session.state.effort;
            app.mode = snapshot.mode;
            app.effort = snapshot.effort;
            app.model = snapshot.model.clone();
            // The status line renders the resolved route, not `app.model`, and until now nothing
            // reassigned it after init or `/model`. A runtime failover commits a different route
            // mid-run, so re-resolve it here through the same one construction `/model` uses.
            // An unbound provider is skipped rather than resolved into a blocked route.
            if let Some(directory) = directory
                && !snapshot.provider_id.is_empty()
            {
                app.route = app.route.reselect(
                    directory,
                    &ModelSelection {
                        provider_id: snapshot.provider_id.clone(),
                        model_id: snapshot.model.clone(),
                    },
                );
            }
            app.telemetry.refresh_economics(&snapshot);
            if route_changed || effort_changed {
                app.telemetry.invalidate_request(&snapshot);
            }
            if route_changed {
                app.telemetry
                    .bind_model_capacity(directory.and_then(|_| app.route.context_window_tokens));
            }
            session.adopt(*snapshot);

            // A durable append/record refusal latches the current writer fail-closed. Re-sending
            // into this same session cannot repair it, even if the original task text was kept for
            // an ordinary provider retry. Only closed, secret-safe record summaries cross EQ.
            let record_failed = summary
                .error
                .as_deref()
                .is_some_and(crate::runtime::KernelError::is_public_record_failure);
            if record_failed {
                app.run.clear_retry();
            }
            let result = summary.current_result();
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
                let detail = if !record_failed && app.run.retry_text().is_some() {
                    format!("{detail}\n\n{}", retry_hint())
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
                app.run.clear_retry();
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
                        crate::machine_projection::budget_remedy(reason)
                    ),
                );
            }
            app.status = format!("idle · last: {canonical_outcome}");
            app.run.observe_terminal_result(result);
            if let Some(trigger) = completion_notification {
                notifier.emit_transport(writer, trigger);
            }
        }
    }
}

/// Queue one workflow-panel mutation on the bounded effect supervisor. The key handler paints the
/// pending label and returns immediately; only this completion path mutates the authoritative
/// inventory.
pub(super) fn queue_workflows_panel_action(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
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
    let request = transcript_effect::Request::Control {
        sender: session.control_sender(),
        control: app_server::Control::Workflow(control),
        interrupt: interrupt.clone(),
        kind: transcript_effect::ControlKind::Workflow,
    };
    if effects.start(request).is_err() {
        app.workflows_panel
            .finish_action("another local control is already pending");
    }
}

pub(super) fn queue_permission_mode(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    next: PermissionMode,
) {
    let request = transcript_effect::Request::Control {
        sender: session.control_sender(),
        control: app_server::Control::SetPermissionMode(next),
        interrupt: interrupt.clone(),
        kind: transcript_effect::ControlKind::PermissionMode(next),
    };
    if effects.start(request).is_ok() {
        app.status = format!("changing mode to {}…", next.label());
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "permission mode not queued: another local control is pending",
        );
    }
}

pub(super) fn queue_effort(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    next: Effort,
) {
    let request = transcript_effect::Request::Control {
        sender: session.control_sender(),
        control: app_server::Control::SetEffort(next),
        interrupt: interrupt.clone(),
        kind: transcript_effect::ControlKind::Effort(next),
    };
    if effects.start(request).is_ok() {
        app.status = format!("changing effort to {}…", next.label());
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "effort not queued: another local control is pending",
        );
    }
}

pub(super) fn queue_permission_capability(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    capability: Capability,
    verdict: Verdict,
) {
    let request = transcript_effect::Request::Control {
        sender: session.control_sender(),
        control: app_server::Control::SetCapabilityRule {
            capability,
            verdict,
        },
        interrupt: interrupt.clone(),
        kind: transcript_effect::ControlKind::Capability {
            capability,
            verdict,
        },
    };
    if effects.start(request).is_ok() {
        app.status = format!("changing {} permission…", cap_label(capability));
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "permission rule not queued: another local control is pending",
        );
    }
}

pub(super) fn queue_model_selection(
    app: &mut App,
    session: &Session,
    directory: &ProviderDirectory,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    selection: ModelSelection,
) {
    let Some(inventory_digest) = session.facts.client_inventory_digest.as_ref() else {
        app.note(
            block::NoticeLevel::Warn,
            "host model inventory is unavailable for this session",
        );
        return;
    };
    let changed =
        session.model() != selection.model_id || app.route.provider_id != selection.provider_id;
    let provider_name = directory
        .entry(&selection.provider_id)
        .map(|entry| entry.display_name().to_owned())
        .unwrap_or_else(|| selection.provider_id.clone());
    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let capabilities = directory.selection_capabilities(&selection);
    let request = transcript_effect::Request::Control {
        sender: session.control_sender(),
        control: app_server::Control::SelectModelV1(
            iteron_protocol::client_inventory::ClientModelSelectionV1 {
                inventory_digest_sha256: inventory_digest.clone(),
                provider_id: selection.provider_id.clone(),
                model_id: selection.model_id.clone(),
                catalog_digest_sha256: catalog_digest,
                capability_digest_sha256: capability_digest,
            },
        ),
        interrupt: interrupt.clone(),
        kind: transcript_effect::ControlKind::Model {
            selection,
            provider_name,
            context_window_tokens: capabilities.context_window_tokens,
            changed,
        },
    };
    if effects.start(request).is_ok() {
        app.status = "changing model…".into();
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "model change not queued: another local control is pending",
        );
    }
}

/// Clear the per-request telemetry after a route or effort change, from a server snapshot.
///
/// The ledger half of the old function reached into `agent.ledger` to reset it; the resident runtime
/// does that on its own side when it applies the transition, so the frontend only has to stop
/// displaying values that no longer describe anything.
pub(super) fn clear_last_turn_telemetry_from(app: &mut App, state: &app_server::SessionSnapshot) {
    app.telemetry.invalidate_request(state);
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
