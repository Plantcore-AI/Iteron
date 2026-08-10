use super::*;

pub(super) fn format_resume_command(run_id: &str) -> String {
    let argument = if !run_id.is_empty()
        && run_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        run_id.to_string()
    } else {
        // Display-only POSIX shell quoting. The command is never executed by Core.
        format!("'{}'", run_id.replace('\'', "'\"'\"'"))
    };
    format!("core --resume {argument}")
}

/// Most transcript blocks an adopted run contributes to the live transcript.
///
/// The kernel replays the WHOLE record — the next turn continues all of it. This is the screen
/// bound only, so a thousand-turn session cannot push the live transcript past its own eviction cap
/// on the way in. The notice above the projection says how much was left out, because a history
/// silently rendered short reads as a shorter conversation than the one the model will see.
pub(super) const MAX_ADOPTED_BLOCKS: usize = 120;

/// Bound on one recorded tool result rendered back into a card.
pub(super) const MAX_ADOPTED_TOOL_OUTPUT_BYTES: usize = 4 * 1024;

/// The `(provider_id, model_id)` an existing record says its last turn dispatched on.
///
/// Same rule the `--resume` startup path applies: the last durable `ModelSelected` is authoritative;
/// a legacy journal that predates provider identity offers only `RunStart.model`, and its model is
/// never used to guess a provider.
pub(super) fn recorded_route(
    events: &[iteron_protocol::Event],
) -> Option<(Option<String>, String)> {
    if let Some(route) = events.iter().rev().find_map(|event| match &event.kind {
        iteron_protocol::EventKind::ModelSelected {
            provider_id,
            model_id,
            ..
        } => Some((Some(provider_id.clone()), model_id.clone())),
        _ => None,
    }) {
        return Some(route);
    }
    events.iter().find_map(|event| match &event.kind {
        iteron_protocol::EventKind::RunStart { model, .. } if !model.is_empty() => {
            Some((None, model.clone()))
        }
        _ => None,
    })
}

/// One recorded tool call, rebuilt from the durable transcript.
pub(super) struct AdoptedTool {
    is_error: bool,
    content: String,
    latency_ms: u64,
}

/// Project an adopted run's durable transcript into settled transcript blocks.
///
/// This renders the RECORD, not a replay of the run: no tool is re-executed, no card is live, and
/// nothing here can start a turn. Returns `(rendered, total)` so the caller can state the bound it
/// applied instead of quietly showing a shorter conversation.
pub(super) fn adopted_transcript_blocks(
    events: &[iteron_protocol::Event],
) -> (Vec<block::BlockKind>, usize) {
    use iteron_protocol::{Block as MessageBlock, EventKind, Role};

    let mut results: std::collections::HashMap<String, AdoptedTool> =
        std::collections::HashMap::new();
    for event in events {
        let EventKind::Message { message } = &event.kind else {
            continue;
        };
        for block in &message.content {
            if let MessageBlock::ToolResult(result) = block {
                results.insert(
                    result.tool_use_id.clone(),
                    AdoptedTool {
                        is_error: result.is_error,
                        content: result.content.clone(),
                        latency_ms: result.latency_ms,
                    },
                );
            }
        }
    }

    let mut blocks = Vec::new();
    for event in events {
        let EventKind::Message { message } = &event.kind else {
            continue;
        };
        for block in &message.content {
            match block {
                MessageBlock::Text { text } if text.trim().is_empty() => {}
                MessageBlock::Text { text } => {
                    let text = ui_safe_text(text);
                    blocks.push(match message.role {
                        Role::User => block::BlockKind::User(text),
                        Role::Assistant => {
                            block::BlockKind::Assistant(crate::markdown::MarkdownDoc::parse(&text))
                        }
                    });
                }
                MessageBlock::Thinking { thinking } if !thinking.trim().is_empty() => {
                    blocks.push(block::BlockKind::Thinking {
                        text: ui_safe_text(thinking),
                        open: false,
                    });
                }
                MessageBlock::ToolUse(call) => {
                    // A recorded call with no recorded result is a real shape: the run stopped
                    // between the two. Saying so beats inventing a status for it.
                    let recorded = results.get(&call.id);
                    let (status, output, elapsed) = match recorded {
                        Some(result) => (
                            if result.is_error {
                                block::ToolStatus::Err
                            } else {
                                block::ToolStatus::Ok
                            },
                            ui_safe_text(&bounded_prefix(
                                &result.content,
                                MAX_ADOPTED_TOOL_OUTPUT_BYTES,
                            )),
                            Some(Duration::from_millis(result.latency_ms)),
                        ),
                        None => (
                            block::ToolStatus::Err,
                            "no recorded result — the run stopped before this tool answered".into(),
                            None,
                        ),
                    };
                    blocks.push(block::BlockKind::Tool(block::ToolCard {
                        name: ui_safe_text(&call.name),
                        args: call.input.clone(),
                        status,
                        output,
                        diff: None,
                        exit_code: None,
                        started: Instant::now(),
                        elapsed,
                        open: false,
                    }));
                }
                MessageBlock::Thinking { .. }
                | MessageBlock::ToolResult(_)
                | MessageBlock::ProviderState(_) => {}
            }
        }
    }

    let total = blocks.len();
    if total > MAX_ADOPTED_BLOCKS {
        blocks.drain(..total - MAX_ADOPTED_BLOCKS);
    }
    (blocks, total)
}

/// Truncate on a char boundary, never mid-UTF-8.
pub(super) fn bounded_prefix(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[truncated for display]", &text[..end])
}

/// Drop every projection of the run being left.
///
/// Retained UI state is per-run exactly as kernel state is: a card, an index entry or a half-streamed
/// paragraph from the previous run would render under the adopted run's identity.
pub(super) fn clear_transcript_for_adoption(app: &mut App) {
    app.transcript.clear();
    app.mark_transcript_changed();
    app.tool_index.clear();
    app.pending_tools.clear();
    app.workflow_index.clear();
    app.workflow_monitor.reset();
    app.workflows_panel.reset();
    app.active_tools.clear();
    app.render_cache.clear();
    app.cur_text.clear();
    app.cur_text_revision = app.cur_text_revision.wrapping_add(1);
    app.cur_doc_revision = app.cur_text_revision;
    app.cur_doc = None;
    app.cur_think.clear();
    app.last_result = None;
    app.retryable_task = None;
    app.resume_handoff = None;
    app.follow_latest();
}

/// Adopt a recorded session into THIS running TUI: the live session takes over that run's journal,
/// identity and transcript, and the next turn continues it.
///
/// # Why the client opens the rollout
///
/// Opening it is what takes the target run's exclusive writer lock, and that is the refusal an
/// operator actually meets — another `core` process is on that session. Taking it here means such an
/// adoption is refused before the resident runtime is asked to do anything, so a session that cannot
/// be adopted cannot disturb the one that is running.
///
/// # Why a route is always sent
///
/// The kernel restores the adopted record's route but cannot resolve a provider for it. Sending the
/// route the session will actually dispatch on — the record's own when this process can build it,
/// this process's current route otherwise — is what makes the adopted run's next request match its
/// own record instead of being refused by the route gate.
pub(super) async fn adopt_session(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    run_id: &str,
) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before resuming another session",
        );
        return;
    }
    if !app.queued.is_empty() || !app.steer_previews.is_empty() {
        // Those submissions were composed for THIS run. Dispatching them into an adopted session
        // would send the operator's words to a conversation they were not written for.
        app.note(
            block::NoticeLevel::Warn,
            format!(
                "{} still pending for this session; send or clear them before resuming another one",
                block::plural(
                    app.queued.len().saturating_add(app.steer_previews.len()),
                    "submission"
                )
            ),
        );
        return;
    }
    let rollout_path = session.rollout_path().to_path_buf();
    let runs = rollout_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let current_run = rollout_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if run_id == current_run {
        app.note(
            block::NoticeLevel::Info,
            "that session is already the live one",
        );
        return;
    }
    let run = iteron_protocol::RunId(run_id.to_owned());
    let tenant = iteron_protocol::TenantId::default();

    // One read of the record serves both halves: the route to bind and the history to render.
    let events = match iteron_record::load_forked(&runs, &run) {
        Ok(events) => events,
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!("cannot read session {}: {error}", ui_safe_text(run_id)),
            );
            return;
        }
    };

    // The record's own route when this process can build it. A provider the operator has not
    // configured, or one that fails to construct, is NOT silently substituted — the session
    // continues on the route this process is already using, and says so.
    let recorded = recorded_route(&events);
    let current_selection = ModelSelection {
        provider_id: app.route.provider_id.clone(),
        model_id: session.model().to_owned(),
    };
    let (selection, built, substituted) = match &recorded {
        Some((Some(provider_id), model_id)) => {
            let candidate = ModelSelection {
                provider_id: provider_id.clone(),
                model_id: model_id.clone(),
            };
            // Building it IS the resolvability test, and the instance is kept: constructing a
            // second one to answer the same question would open a second client for nothing.
            match directory.build(&candidate) {
                Ok(provider) => (candidate, Some(provider), None),
                Err(error) => (
                    current_selection,
                    None,
                    Some(format!(
                        "the recorded route {provider_id}:{model_id} is not usable here ({error})"
                    )),
                ),
            }
        }
        Some((None, model_id)) => (
            current_selection,
            None,
            Some(format!(
                "this session predates provider identity and records only model `{model_id}`"
            )),
        ),
        None => (
            current_selection,
            None,
            Some("this session records no route".into()),
        ),
    };
    let provider = match built {
        Some(provider) => provider,
        None => match directory.build(&selection) {
            Ok(provider) => provider,
            Err(error) => {
                app.note(
                    block::NoticeLevel::Err,
                    format!("cannot resume that session here: {error}"),
                );
                return;
            }
        },
    };

    // Takes the target run's exclusive writer lock. The live run keeps its own until the runtime
    // swaps them, so a refusal here costs the operator nothing.
    let rollout = match iteron_record::Rollout::open_existing(&runs, &run, tenant) {
        Ok(rollout) => rollout,
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!(
                    "cannot take over session {}: {error}. Another core process may still be \
                     running it.",
                    ui_safe_text(run_id)
                ),
            );
            app.prepare_resume_handoff(run_id);
            return;
        }
    };

    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let capabilities = directory.selection_capabilities(&selection);
    let reply = session
        .control(app_server::Control::AdoptRun(Box::new(
            app_server::AdoptRun {
                rollout,
                fresh: false,
                route: Box::new(app_server::ModelSelection {
                    provider,
                    provider_id: selection.provider_id.clone(),
                    model_id: selection.model_id.clone(),
                    catalog_digest,
                    capability_digest,
                    context_window_tokens: capabilities.context_window_tokens,
                    max_output_tokens: capabilities.max_output_tokens,
                }),
            },
        )))
        .await;
    let (adopted, state, blocked) = match reply {
        Some(app_server::ControlReply::Adopted {
            adopted,
            snapshot,
            blocked,
        }) => (adopted, snapshot, blocked),
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason);
            // The documented restart still works, so the operator keeps a way through.
            app.prepare_resume_handoff(run_id);
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

    // Everything below renders the identity the RUNTIME reached. The frontend never displays a run
    // the next turn would not continue.
    clear_transcript_for_adoption(app);
    let (blocks, total) = adopted_transcript_blocks(&events);
    let rendered = blocks.len();
    if rendered < total {
        app.note(
            block::NoticeLevel::Info,
            format!(
                "showing the last {rendered} of {total} recorded transcript blocks; the model \
                 continues from all of them"
            ),
        );
    }
    for kind in blocks {
        app.push_block(kind);
    }

    session.adopt_run(adopted.rollout_path.clone(), (*state).clone());
    app.session_name = session_display_name(&adopted.rollout_path);
    app.mode = state.mode;
    app.effort = state.effort;
    app.model = state.model.clone();
    app.cost = state.cost.clone();
    app.turns = adopted.turns;
    app.route = app.route.reselect(
        directory,
        &ModelSelection {
            provider_id: selection.provider_id.clone(),
            model_id: state.model.clone(),
        },
    );
    app.model_context_window = capabilities.context_window_tokens;
    clear_last_turn_telemetry_from(app, &state);
    app.status = format!("idle · resumed {}", adopted.run_id);

    if let Some(reason) = substituted {
        app.note(
            block::NoticeLevel::Warn,
            format!(
                "{reason}; this session continues on {}:{}",
                selection.provider_id, selection.model_id
            ),
        );
    } else if let Some((recorded_provider, recorded_model)) = adopted
        .recorded_route
        .as_ref()
        .filter(|(provider_id, model_id)| {
            provider_id != &selection.provider_id || model_id != &selection.model_id
        })
    {
        // The kernel reports the route it restored FROM THE RECORD, independently of what this
        // frontend parsed out of the same events. A disagreement means the session is dispatching
        // on a route its own record does not name, which the operator has to be told.
        app.note(
            block::NoticeLevel::Warn,
            format!(
                "the runtime restored route {recorded_provider}:{recorded_model} from that record, \
                 but this session dispatches on {}:{}",
                selection.provider_id, selection.model_id
            ),
        );
    }
    app.note(
        block::NoticeLevel::Ok,
        format!(
            "resumed {} here · {} · {} · {}:{} · left {}",
            adopted.run_id,
            block::plural(adopted.messages, "message"),
            block::plural(adopted.turns as usize, "turn"),
            selection.provider_id,
            state.model,
            adopted.previous_run_id
        ),
    );

    // The session moved and cannot dispatch. The identity above is still rendered — it is where the
    // runtime is — and this says, last and loudest, that the process has to be restarted to use it.
    if let Some(blocked) = blocked {
        app.note(block::NoticeLevel::Err, blocked);
        app.prepare_resume_handoff(&adopted.run_id);
    }
}
