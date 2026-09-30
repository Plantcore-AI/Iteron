use super::{App, ModelSelection, ProviderDirectory, Session, app_server, block, ui_safe_text};
use std::path::Path;
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

pub(super) struct PreparedAdoption {
    pub(super) fresh: bool,
    pub(super) control: app_server::Control,
    pub(super) run_id: String,
    pub(super) events: Vec<iteron_protocol::Event>,
    pub(super) selection: ModelSelection,
    pub(super) substituted: Option<String>,
    pub(super) context_window_tokens: Option<u64>,
}

pub(super) enum PreparedAdoptionResult {
    Ready(PreparedAdoption),
    Failed {
        message: String,
        handoff_run: Option<String>,
    },
}

/// Queue one native preparation request without giving the compositor ownership of its task.
pub(super) fn start_adopt_session(
    app: &mut App,
    session: &Session,
    directory: &ProviderDirectory,
    run_id: String,
) {
    if !adoption_draft_ready(app) {
        return;
    }
    let Some(scope) = session.client.thread_snapshot_v1() else {
        app.note(
            block::NoticeLevel::Warn,
            "public session scope unavailable; resume was not started",
        );
        return;
    };
    if run_id == scope.run_id.0 {
        app.note(
            block::NoticeLevel::Info,
            "that session is already the live one",
        );
        return;
    }
    let source = super::session_navigation::PreparationSource {
        runs: session
            .rollout_path()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default(),
        directory: directory.clone(),
        selection: ModelSelection {
            provider_id: app.route.provider_id.clone(),
            model_id: session.model().to_owned(),
        },
        kind: super::session_navigation::PreparationKind::Existing(run_id.clone()),
    };
    if app.navigation.queue_adoption(&scope, source) {
        app.status = format!("opening session {}…", ui_safe_text(&run_id));
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "session preparation is still running; wait for its physical worker to finish",
        );
    }
}
pub(super) fn start_fresh_session(app: &mut App, session: &Session, directory: &ProviderDirectory) {
    if !adoption_draft_ready(app) {
        return;
    }
    let Some(scope) = session.client.thread_snapshot_v1() else {
        app.note(
            block::NoticeLevel::Warn,
            "public session scope unavailable; session creation was not started",
        );
        return;
    };
    let source = super::session_navigation::PreparationSource {
        runs: session
            .rollout_path()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default(),
        directory: directory.clone(),
        selection: ModelSelection {
            provider_id: app.route.provider_id.clone(),
            model_id: session.model().to_owned(),
        },
        kind: super::session_navigation::PreparationKind::Fresh,
    };
    if app.navigation.queue_adoption(&scope, source) {
        app.status = "creating session…".into();
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "session preparation is still running; wait for its physical worker to finish",
        );
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

/// Replace the visible conversation with the bounded projection of one durable rollout.
///
/// Both startup `--resume` and in-process `/resume` use this seam so the operator sees the same
/// history regardless of how the runtime acquired the rollout. The model still receives the full
/// reconstructed transcript; only this display projection is bounded.
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
