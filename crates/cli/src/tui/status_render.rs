//! Runtime observation status-line and activity projection rendering.

use super::{
    App, Duration, Effort, EffortApplication, FirstTokenState, Frame, Line, Modifier, Paragraph,
    PermissionMode, PresentedActivity, Rect, Span, Style, clip_spans, clip_text,
    effort_status_label, fmt_mmss, route_label, spans_width, spinner, status_line, surface,
};

pub(super) fn render_lr_line(
    f: &mut Frame,
    area: Rect,
    left: Vec<Span<'static>>,
    right: Vec<Span<'static>>,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let left_w = spans_width(&left);
    let right_w = spans_width(&right);
    let gap = area.width.saturating_sub(left_w.saturating_add(right_w));
    let mut spans = left;
    if gap > 0 {
        spans.push(Span::raw(" ".repeat(gap as usize)));
    }
    spans.extend(right);
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

pub(super) fn effort_status_accent(app: &App) -> status_line::Accent {
    match app.effort_application {
        Some(EffortApplication::Mapped { requested, sent }) if requested != sent => {
            status_line::Accent::Warning
        }
        Some(
            EffortApplication::BudgetBased { .. }
            | EffortApplication::ToggleOnly { .. }
            | EffortApplication::Unsupported { .. },
        ) => status_line::Accent::Warning,
        _ => status_line::Accent::Model,
    }
}

/// Build the factual portion of the footer through the public status-line contract. Runtime/UI
/// activity affordances remain separate groups, but model/tokens/cost/context/session have one
/// renderer and one unknown-value policy across the product.
pub(super) fn canonical_statusline(app: &App) -> String {
    let tokens = app.last_turn_usage.map(|usage| {
        usage
            .input
            .saturating_add(usage.output)
            .saturating_add(usage.cache_creation)
            .saturating_add(usage.cache_read)
            .saturating_add(usage.thinking)
    });
    canonical_statusline_with_tokens(app, tokens)
}

pub(super) fn canonical_statusline_with_tokens(app: &App, tokens: Option<u64>) -> String {
    use iteron_statusline::{Field, StatusLine, StatusSnapshot, Value};
    use std::sync::OnceLock;

    static LINE: OnceLock<StatusLine> = OnceLock::new();
    let line = LINE.get_or_init(|| {
        StatusLine::from_names(["model", "tokens", "cost", "context", "session"])
            .expect("the built-in status fields are closed and valid")
    });
    let model = route_label(app);
    let context = app
        .model_context_window
        .filter(|window| *window > 0)
        .map(|window| {
            let used = app
                .last_context
                .map(|context| context.total_tokens as u64)
                .or_else(|| app.last_turn_usage.map(request_input_tokens))
                .unwrap_or_default()
                .saturating_add(u64::from(app.reserved_output_tokens.unwrap_or_default()));
            let left = window.saturating_sub(used).saturating_mul(100) / window;
            u8::try_from(left.min(100)).unwrap_or(100)
        });
    let cost_milli = app
        .cost
        .usd()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .map(|value| (value * 1_000.0).round() as u64);
    let snapshot = StatusSnapshot::new(
        app.history.revision(),
        [
            (
                Field::Model,
                if model.is_empty() {
                    Value::Unknown
                } else {
                    Value::Text(model)
                },
            ),
            (Field::Tokens, tokens.map_or(Value::Unknown, Value::Count)),
            (
                Field::CostUsd,
                cost_milli.map_or(Value::Unknown, Value::Milli),
            ),
            (
                Field::ContextPercent,
                context.map_or(Value::Unknown, Value::Percent),
            ),
            (Field::SessionId, Value::Text(app.session_name.clone())),
        ],
    )
    .expect("the frontend supplies each closed status field once with its declared type");
    line.render_snapshot(&snapshot)
}

pub(super) fn status_right_groups(app: &App, density: surface::Density) -> Vec<status_line::Group> {
    use status_line::{Accent, Group};

    // Mouse ownership yields first under width pressure; the hint row independently exposes the
    // Ctrl-T transition. The label always says who owns the next drag/wheel gesture.
    let mut groups = vec![Group::single(
        app.mouse_capture.status_label(),
        Accent::Metadata,
    )];
    if app.keymap_status != "keys:standard" {
        groups.push(Group::single(app.keymap_status.clone(), Accent::Mode));
    }
    // A live QuickJS workflow run announces itself only through its transcript card, and a
    // terminal too short for that card — the workflow region negotiates down to zero rows before
    // the status row gives up its last one (`surface::Surface::resolve`) — showed no sign that a
    // run was still going at all. This bit is that sign and nothing more: `⟳ n run(s)`, the
    // smallest thing that answers "is something still running?".
    //
    // It follows the keymap bit's rule — say it only when it is not the default — so an operator
    // with no workflow running never pays a column for it. It is placed here, immediately after
    // mouse ownership, because it is a redundancy: whenever the region itself is on screen the
    // region is the better answer, so under width pressure this yields ahead of context, mode,
    // the pending count, and the route/effort identity, which have no second place to be read.
    let live_runs = app.workflow_monitor.live_count();
    if live_runs > 0 {
        groups.push(Group::single(
            format!(
                "\u{27f3} {live_runs} run{}", // ⟳
                if live_runs == 1 { "" } else { "s" }
            ),
            Accent::Progress,
        ));
    }
    if density == surface::Density::Wide && app.turns > 0 {
        groups.push(Group::single(
            format!("turn {}", app.turns),
            Accent::Metadata,
        ));
    }
    if density == surface::Density::Wide && app.workspace_dirty == Some(true) {
        groups.push(Group::single("dirty", Accent::Warning));
    }
    if density == surface::Density::Wide
        && let Some(latency) = app.last_run_latency
    {
        groups.push(Group::single(
            format!("last {}", fmt_mmss(latency)),
            Accent::Metadata,
        ));
    }
    if app.running && !app.assistant.authority().is_empty() {
        let approximate_tokens = app.assistant.approximate_tokens();
        groups.push(Group::single(
            format!("~{approximate_tokens} tok"),
            Accent::Usage,
        ));
    }
    if density != surface::Density::Compact
        && let Some(usage) = app.last_turn_usage
    {
        groups.push(Group::single(
            format!("cache {:.0}%", usage.cache_hit_ratio() * 100.0),
            Accent::Usage,
        ));
    }
    if app.mode != PermissionMode::Default {
        groups.push(Group::single(app.mode.label(), Accent::Mode));
    }
    let pending = app
        .input_lanes
        .steers()
        .len()
        .saturating_add(app.input_lanes.queued().len());
    if pending > 0 {
        groups.push(Group::single(
            format!("{pending} pending"),
            Accent::Progress,
        ));
    }
    // The canonical renderer owns model/tokens/cost/context/session and their unknown semantics.
    // Keep it near the high-priority end, while effort remains an Iteron-specific semantic beside
    // it rather than being smuggled into the model field.
    groups.push(Group::single(canonical_statusline(app), Accent::Metadata));
    // Ultracode is a harness MODE (internal fan-out orchestration), not just a thinking level, so
    // it announces itself once, the way the permission mode does. The adjacent effort segment
    // reports only the adapter's reasoning level/application.
    if app.effort == Effort::Ultracode {
        groups.push(Group::single("✦ ultracode", Accent::Mode));
    }
    let effort = effort_status_label(app);
    groups.push(Group::single(effort, effort_status_accent(app)));
    groups
}

#[cfg(test)]
pub(super) fn status_right_bits(app: &App, density: surface::Density) -> Vec<String> {
    status_right_groups(app, density)
        .iter()
        .map(status_line::Group::text)
        .collect()
}

pub(super) fn activity_label(event: &iteron_protocol::ActivityEvent) -> &'static str {
    use iteron_protocol::ActivityDetailCode as Detail;
    match event.detail_code {
        Some(Detail::Boot) => "starting Iteron",
        Some(Detail::Config) => "loading configuration",
        Some(Detail::AgentDiscovery) => "discovering agents",
        Some(Detail::PluginVerification) => "verifying plugins",
        Some(Detail::ProviderRefresh) => "refreshing providers",
        Some(Detail::FirstPaint) => "painting interface",
        Some(Detail::HistoryHydrate) => "loading prompt history",
        Some(Detail::SessionIndex) => "indexing sessions",
        Some(Detail::WorkflowRehydrate) => "restoring workflows",
        Some(Detail::SubmissionAdmission) => "admitting submission",
        Some(Detail::ContextAssembly) => "assembling context",
        Some(Detail::HookGate) => "running hook gate",
        Some(Detail::RoutePermit) => "waiting for route permit",
        Some(Detail::RequestSerialization) => "building request",
        Some(Detail::TransportConnect) => "connecting to provider",
        Some(Detail::RequestSent) => "request sent · waiting for provider",
        Some(Detail::WaitingFirstByte) => "request sent · waiting for first byte",
        Some(Detail::WaitingFirstToken) => "accepted · waiting for first token",
        Some(Detail::Reasoning) if event.kind.is_reasoning() => "thinking",
        Some(Detail::Reasoning) => "reasoning activity",
        Some(Detail::Responding) => "responding",
        Some(Detail::ToolProposed) => "tool proposed",
        Some(Detail::ToolHook) => "running tool hook",
        Some(Detail::ToolApproval) => "waiting for tool approval",
        Some(Detail::ToolQueued) => "tool queued",
        Some(Detail::ToolRunning) => "tool running",
        Some(Detail::ToolPostProcessing) => "processing tool result",
        Some(Detail::RetryBackoff) => "retry backoff",
        Some(Detail::RouteFailover) => "switching provider route",
        Some(Detail::Compaction) => "compacting context",
        Some(Detail::Verification) => "verifying result",
        Some(Detail::Checkpoint) => "writing checkpoint",
        Some(Detail::RecordCommit) => "committing run record",
        Some(Detail::StopHooks) => "running stop hooks",
        Some(Detail::WorkflowResultPersist) => "saving workflow result",
        Some(Detail::AnswerComplete) => "answer complete",
        Some(Detail::Finalizing) => "finalizing",
        Some(Detail::InputReady) => "input ready",
        None => match event.kind {
            iteron_protocol::ActivityKind::ProviderReasoning => "thinking",
            iteron_protocol::ActivityKind::ModelRequest => "model request",
            iteron_protocol::ActivityKind::Tool => "tool activity",
            iteron_protocol::ActivityKind::Workflow => "workflow activity",
            iteron_protocol::ActivityKind::Attachment => "attachment",
            iteron_protocol::ActivityKind::Completion => "completion",
            iteron_protocol::ActivityKind::HistoryHydration => "prompt history",
            iteron_protocol::ActivityKind::SessionIndex => "session index",
            iteron_protocol::ActivityKind::WorkflowHydration => "workflow restore",
            iteron_protocol::ActivityKind::TerminalProbe => "terminal probe",
            iteron_protocol::ActivityKind::Verification => "verification",
            iteron_protocol::ActivityKind::Persistence => "persistence",
            iteron_protocol::ActivityKind::Finalization => "finalizing",
            iteron_protocol::ActivityKind::Cancellation => "cancelling",
            iteron_protocol::ActivityKind::Startup => "starting",
        },
    }
}

pub(super) fn visible_activity(app: &App) -> Option<(&PresentedActivity, Duration)> {
    if app.first_token_stall().is_some() {
        return None;
    }
    let activity = app
        .activities
        .values()
        .max_by_key(|activity| activity.event.updated_at_unix_ms)?;
    let elapsed = activity.observed_at.elapsed();
    (elapsed >= Duration::from_millis(250)).then_some((activity, elapsed))
}

pub(super) fn render_status(f: &mut Frame, area: Rect, density: surface::Density, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let th = &app.theme;
    let muted = Style::default().fg(th.muted);
    let accent = Style::default().fg(th.accent).add_modifier(Modifier::BOLD);
    let success = Style::default().fg(th.success).add_modifier(Modifier::BOLD);
    let warn = Style::default().fg(th.warn).add_modifier(Modifier::BOLD);
    let error = Style::default().fg(th.error).add_modifier(Modifier::BOLD);

    let mut left = if app.draining {
        vec![
            Span::styled("◆ ", warn),
            Span::styled("draining session", warn),
        ]
    } else if app.force_cancelling {
        vec![
            Span::styled("◆ ", error),
            Span::styled("stronger cancellation requested", error),
        ]
    } else if app.pending.is_some() {
        vec![
            Span::styled("◆ ", warn),
            Span::styled("approval required", warn),
        ]
    } else if app.interrupting {
        vec![
            Span::styled("◆ ", warn),
            Span::styled("interrupt requested · stopping now", warn),
        ]
    } else if !app.viewport.follows_tail() {
        let unread = if !app.viewport.has_unread() {
            String::new()
        } else {
            " · new output".to_string()
        };
        let anchor = if app.viewport.has_missing_anchor() {
            " · prior block unavailable"
        } else {
            ""
        };
        vec![Span::styled(
            format!("↑ reading history{unread}{anchor} · ctrl+end to follow"),
            Style::default().fg(th.warn),
        )]
    } else if let Some((activity, elapsed)) = visible_activity(app) {
        let mut label = activity_label(&activity.event).to_owned();
        if elapsed >= Duration::from_secs(1) {
            label.push_str(&format!(" · {}", fmt_mmss(elapsed)));
        }
        if activity.event.limit > 1 {
            label.push_str(&format!(
                " · attempt {}/{}",
                activity.event.attempt, activity.event.limit
            ));
        }
        if let Some(progress) = activity.event.progress {
            if activity.event.detail_code == Some(iteron_protocol::ActivityDetailCode::ToolQueued) {
                label.push_str(&format!(
                    " · {}/{} permits",
                    progress.completed, progress.total
                ));
            } else {
                label.push_str(&format!(" · {}/{}", progress.completed, progress.total));
            }
        }
        if elapsed >= Duration::from_secs(2) {
            label.push_str(match activity.event.cancelability {
                iteron_protocol::ActivityCancelability::None => " · /status for remedy",
                _ => " · Esc to cancel",
            });
        }
        vec![
            Span::styled(
                format!("{} ", spinner()[app.spin % spinner().len()]),
                accent,
            ),
            Span::styled(label, accent),
        ]
    } else if let Some(stall) = app.first_token_stall() {
        // A dead connection and a slow prefill are the same picture for a full minute unless the
        // interface says which one it is looking at, and it knows: no token has arrived yet
        // (I-64). Both states still spin, because the request is genuinely still open.
        let style = match stall.state {
            FirstTokenState::Slow => accent,
            FirstTokenState::Stalled => warn,
        };
        vec![
            Span::styled(format!("{} ", spinner()[app.spin % spinner().len()]), style),
            Span::styled(stall.label(), style),
        ]
    } else if app.running {
        let phase = match app.status.trim() {
            "" | "running…" => "working",
            other => other,
        };
        let mut spans = vec![
            Span::styled(
                format!("{} ", spinner()[app.spin % spinner().len()]),
                accent,
            ),
            Span::styled(phase.to_string(), accent),
        ];
        if let Some((activity, count)) = app.tools.active_summary() {
            let activity = clip_text(activity, (area.width / 3).max(12));
            spans.push(Span::styled(format!(" · {activity}"), muted));
            if count > 1 {
                spans.push(Span::styled(format!(" +{}", count - 1), muted));
            }
        }
        if let Some(product_turn) = &app.product_turn_status {
            spans.push(Span::styled(format!(" · {product_turn}"), muted));
        }
        if let Some(started) = app.run_started {
            spans.push(Span::styled(
                format!(" · {}", fmt_mmss(started.elapsed())),
                muted,
            ));
        }
        spans
    } else {
        let label = if app.status.trim().is_empty() || app.status.trim() == "idle" {
            "ready".to_string()
        } else {
            app.status.clone()
        };
        let normalized = label.to_ascii_lowercase();
        let beacon = if normalized.contains("failed")
            || normalized.contains("error")
            || normalized.contains("stuck")
        {
            error
        } else if normalized.contains("budget") || normalized.contains("interrupt") {
            warn
        } else if label == "ready" || normalized.contains("success") {
            success
        } else {
            accent
        };
        vec![Span::styled("◆ ", beacon), Span::styled(label, muted)]
    };
    // Right-side metadata is progressively disclosed. When it does not fit, low-priority economics
    // disappear first; the route/pending state at the end survives and is clipped explicitly.
    let mut groups = status_right_groups(app, density);
    let left_budget = if groups.is_empty() {
        area.width
    } else {
        area.width.saturating_mul(2) / 3
    };
    if spans_width(&left) > left_budget {
        let summary = left
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        left = vec![Span::styled(clip_text(&summary, left_budget), accent)];
    }
    let left_w = spans_width(&left);
    let available = area.width.saturating_sub(left_w.saturating_add(2));
    while groups.len() > 1 && status_line::width(&groups) > available {
        groups.remove(0);
    }
    let right = clip_spans(status_line::spans(&groups, th), available);
    render_lr_line(f, area, left, right);
}
