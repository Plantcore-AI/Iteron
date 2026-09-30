use super::{App, ModelSelection, ProviderDirectory, Session, app_server, block, ui_safe_text};
use std::time::{Duration, Instant};

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
    format!("iteron --resume {argument}")
}

/// Most transcript blocks an adopted run contributes to the live transcript.
///
/// The kernel replays the WHOLE record — the next turn continues all of it. This is the screen
/// bound only, so a thousand-turn session cannot push the live transcript past its own eviction cap
/// on the way in. The notice above the projection says how much was left out, because a history
/// silently rendered short reads as a shorter conversation than the one the model will see.
#[cfg(test)]
pub(super) const MAX_ADOPTED_BLOCKS: usize = 120;

/// Bound on one recorded tool result rendered back into a card.
#[cfg(test)]
pub(super) const MAX_ADOPTED_TOOL_OUTPUT_BYTES: usize = 4 * 1024;

/// The `(provider_id, model_id)` an existing record says its last turn dispatched on.
///
/// Same rule the `--resume` startup path applies: the last durable `ModelSelected` is authoritative;
/// a legacy journal that predates provider identity offers only `RunStart.model`, and its model is
/// never used to guess a provider.
#[cfg(test)]
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

/// Submit IDs through the same trusted host control used by external clients. No provider or
/// physical journal constructor is available to this presentation module.
pub(super) fn start_adopt_session(
    app: &mut App,
    session: &Session,
    _directory: &ProviderDirectory,
    run_id: String,
) {
    queue_navigation(
        app,
        session,
        |scope| iteron_protocol::session_navigation::SessionNavigationV1::Resume {
            thread_id: scope.thread_id.clone(),
            run_id: scope.run_id.clone(),
            target_run_id: iteron_protocol::RunId(run_id),
        },
        "opening session…",
    );
}
pub(super) fn start_fresh_session(
    app: &mut App,
    session: &Session,
    _directory: &ProviderDirectory,
) {
    queue_navigation(
        app,
        session,
        |scope| iteron_protocol::session_navigation::SessionNavigationV1::New {
            thread_id: scope.thread_id.clone(),
            run_id: scope.run_id.clone(),
        },
        "creating session…",
    );
}
pub(super) fn start_fork_session(app: &mut App, session: &Session) {
    queue_navigation(
        app,
        session,
        |scope| iteron_protocol::session_navigation::SessionNavigationV1::Fork {
            thread_id: scope.thread_id.clone(),
            run_id: scope.run_id.clone(),
            through_seq: None,
        },
        "forking session…",
    );
}
fn queue_navigation(
    app: &mut App,
    session: &Session,
    command: impl FnOnce(
        &iteron_protocol::product_contract::ThreadSnapshotV1,
    ) -> iteron_protocol::session_navigation::SessionNavigationV1,
    label: &str,
) {
    if !adoption_draft_ready(app) {
        return;
    }
    let Some(scope) = session.client.thread_snapshot_v1() else {
        app.note(
            block::NoticeLevel::Warn,
            "public session scope unavailable; navigation was not started",
        );
        return;
    };
    if app
        .navigation
        .queue_adoption(&scope, session.control_sender(), command(&scope))
    {
        app.status = label.into();
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "session navigation is still pending; wait for the host result",
        );
    }
}

pub(super) fn apply_navigated_session(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    reply: app_server::NavigatedSession,
) {
    let app_server::NavigatedSession {
        presentation: fact,
        adopted,
        snapshot,
        tunables_checkpoint,
        compaction_trigger_tokens,
    } = reply;
    app.navigation.cancel_preview();
    let origin = app.attachments.invalidate();
    super::composer_images::restore_unprepared_origin(app, origin);
    app.completions.dismiss();
    app.close_picker_restore_theme();
    project_host_transcript(app, &fact.transcript);
    session.adopt_run(
        adopted.rollout_path,
        tunables_checkpoint,
        compaction_trigger_tokens,
        snapshot.clone(),
    );
    app.session_name = if fact.fresh {
        "New session".into()
    } else {
        fact.run_id.0.clone()
    };
    app.mode = snapshot.mode;
    app.effort = snapshot.effort;
    app.model = snapshot.model.clone();
    app.cost = snapshot.cost.clone();
    app.turns = if fact.fresh { 0 } else { fact.turns };
    app.route = app.route.reselect(
        directory,
        &ModelSelection {
            provider_id: fact.provider_id.clone(),
            model_id: fact.model_id.clone(),
        },
    );
    app.model_context_window = fact.context_window_tokens;
    super::clear_last_turn_telemetry_from(app, &snapshot);
    app.status = if fact.fresh {
        "ready".into()
    } else {
        format!("idle · resumed {}", ui_safe_text(&fact.run_id.0))
    };
    if let Some(reason) = fact.substituted_route {
        app.note(
            block::NoticeLevel::Warn,
            format!("{reason}; selected {}:{}", fact.provider_id, fact.model_id),
        );
    }
    app.note(
        block::NoticeLevel::Ok,
        format!(
            "{} {} · {} messages · {} turns · left {}",
            if fact.fresh { "created" } else { "adopted" },
            fact.run_id.0,
            fact.messages,
            fact.turns,
            fact.origin_run_id.0
        ),
    );
    if let Some(reason) = fact.blocked {
        app.note(block::NoticeLevel::Err, reason);
        app.prepare_resume_handoff(&fact.run_id.0);
        app.status = "idle · selected session requires restart".into();
    }
}
pub(super) fn project_host_transcript(
    app: &mut App,
    transcript: &iteron_protocol::session_navigation::SessionTranscriptV1,
) {
    use iteron_protocol::session_navigation::SessionTranscriptContentV1;
    clear_transcript_for_adoption(app);
    if transcript.omitted_blocks > 0 {
        app.note(
            block::NoticeLevel::Info,
            format!(
                "showing {} of {} verified transcript blocks; {} omitted from display",
                transcript.blocks.len(),
                transcript.total_blocks,
                transcript.omitted_blocks
            ),
        );
    }
    for row in &transcript.blocks {
        let kind = match &row.content {
            SessionTranscriptContentV1::User { text } => block::BlockKind::User(text.clone()),
            SessionTranscriptContentV1::Assistant { text } => {
                block::BlockKind::Assistant(crate::markdown::MarkdownDoc::parse(text))
            }
            SessionTranscriptContentV1::Thinking { text } => block::BlockKind::Thinking {
                text: text.clone(),
                open: false,
            },
            SessionTranscriptContentV1::Tool {
                name,
                recorded_is_error: None,
                output,
                ..
            } => block::BlockKind::Notice {
                level: block::NoticeLevel::Warn,
                text: format!("recorded tool {name} · outcome unavailable · {output}"),
            },
            SessionTranscriptContentV1::Tool {
                name,
                args,
                recorded_is_error,
                output,
                latency_ms,
            } => block::BlockKind::Tool(block::ToolCard {
                name: name.clone(),
                args: args.clone(),
                status: match recorded_is_error {
                    Some(false) => block::ToolStatus::Ok,
                    _ => block::ToolStatus::Err,
                },
                output: output.clone(),
                diff: None,
                exit_code: None,
                started: Instant::now(),
                elapsed: latency_ms.map(Duration::from_millis),
                open: false,
            }),
        };
        app.push_block(kind);
        if row.content_truncated {
            app.note(
                block::NoticeLevel::Info,
                "recorded content truncated for display; full verified history remains in the host",
            );
        }
    }
}

fn adoption_draft_ready(app: &mut App) -> bool {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before switching sessions",
        );
        return false;
    }
    if !app.input_lanes.queued().is_empty() || !app.input_lanes.steers().is_empty() {
        app.note(
            block::NoticeLevel::Warn,
            "send or clear pending submissions before switching sessions",
        );
        return false;
    }
    true
}

/// One recorded tool call, rebuilt from the durable transcript.
#[cfg(test)]
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
#[cfg(test)]
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
                                iteron_tunables::param_integer(
                                    "cli.tui.session_adoption.max_adopted_tool_output_bytes",
                                    MAX_ADOPTED_TOOL_OUTPUT_BYTES,
                                ),
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
                | MessageBlock::ToolImage(_)
                | MessageBlock::ProviderState(_) => {}
            }
        }
    }

    let total = blocks.len();
    if total
        > iteron_tunables::param_integer(
            "cli.tui.session_adoption.max_adopted_blocks",
            MAX_ADOPTED_BLOCKS,
        )
    {
        blocks.drain(
            ..total
                - iteron_tunables::param_integer(
                    "cli.tui.session_adoption.max_adopted_blocks",
                    MAX_ADOPTED_BLOCKS,
                ),
        );
    }
    (blocks, total)
}

/// Truncate on a char boundary, never mid-UTF-8.
#[cfg(test)]
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
    app.geometry.clear();
    app.assistant.reset();
    app.last_result = None;
    app.retryable_task = None;
    app.resume_handoff = None;
    app.follow_latest();
}

/// Replace the visible conversation with the bounded projection of one durable rollout.
///
/// Both startup `--resume` and in-process `/resume` use this seam so the operator sees the same
/// history regardless of how the runtime acquired the rollout. The model still receives the full
/// reconstructed transcript; only this display projection is bounded.
#[cfg(test)]
pub(super) fn project_recorded_transcript(app: &mut App, events: &[iteron_protocol::Event]) {
    clear_transcript_for_adoption(app);
    let (blocks, total) = adopted_transcript_blocks(events);
    let rendered = blocks.len();
    if rendered < total {
        app.note(
            block::NoticeLevel::Info,
            format!(
                "showing the last {rendered} of {total} recorded transcript blocks; the model continues from all of them"
            ),
        );
    }
    for kind in blocks {
        app.push_block(kind);
    }
}
