//! Full-frame retained conversation, hint and workflow chrome rendering.

use super::{
    App, Frame, InputDestination, Line, Modifier, Paragraph, PopupRow, Rect, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Span, Style, block, cached_input_destination,
    capability_can_be_remembered, clip_text, hyperlink, live_markdown, render_composer,
    render_list_popup, render_lr_line, render_pending_lanes, render_status, surface, theme,
    transcript_layout, transcript_viewer, ui_safe_text, workflow_panel_runs, workflows_panel,
};

pub(super) fn route_label(app: &App) -> String {
    // The statusline used to build `provider/model` out of two loose `App` fields. It reads the
    // one route view now, so it cannot label a request the run is not making (I-26).
    app.route.short_label()
}

pub(super) fn footer_spans(text: &str, theme: &theme::Theme) -> Vec<Span<'static>> {
    const KEYS: &[&str] = &[
        "enter",
        "tab",
        "esc",
        "ctrl+j",
        "ctrl+v",
        "ctrl+z",
        "ctrl+g",
        "ctrl+r",
        "alt+↑",
        "alt+backspace",
        "ctrl+end",
        "y",
        "a",
        "n",
        "n/esc",
        "/",
        "@",
        "!",
        "?",
    ];
    let mut spans = Vec::new();
    for (index, item) in text.split(" · ").enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", Style::default().fg(theme.faint)));
        }
        let (head, tail) = item.split_once(' ').unwrap_or((item, ""));
        if KEYS.contains(&head) {
            let key_style = if theme.mono {
                Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            };
            spans.push(Span::styled(head.to_string(), key_style));
            if !tail.is_empty() {
                spans.push(Span::styled(
                    format!(" {tail}"),
                    Style::default().fg(theme.muted),
                ));
            }
        } else {
            spans.extend(crate::semantic_text::spans(
                item,
                crate::semantic_text::Tone::Muted,
                theme,
            ));
        }
    }
    spans
}

pub(super) fn render_hint(f: &mut Frame, area: Rect, density: surface::Density, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let text = app.editor.text();
    let left = if app.pending_mcp_input.is_some() {
        if density == surface::Density::Compact {
            "enter answer · esc decline"
        } else {
            "enter sends JSON · ctrl+j newline · esc declines · ctrl-c declines and interrupts"
        }
    } else if app.pending.is_some() {
        let rememberable = app
            .pending
            .as_ref()
            .is_some_and(|pending| capability_can_be_remembered(pending.cap));
        if density == surface::Density::Compact && rememberable {
            "y once · a session-wide · n deny"
        } else if density == surface::Density::Compact {
            "y once · n deny"
        } else if rememberable {
            "y allow once · a remembers this capability for the session · n/esc deny"
        } else {
            "y allow once · n/esc deny · approval is required every time"
        }
    } else if app.is_resume_handoff_draft() {
        "copy to a new terminal · enter keeps draft · esc clear"
    } else if app.running && !text.is_empty() {
        match cached_input_destination(true, app.interrupting, app.editor.draft_shape()) {
            InputDestination::ImmediateCommand if density == surface::Density::Compact => {
                "enter control · ctrl+j newline · esc stop"
            }
            InputDestination::ImmediateCommand => {
                "enter runs this control now · ctrl+j newline · esc interrupt"
            }
            InputDestination::AfterTurn if density == surface::Density::Compact => {
                "enter queue · ctrl+j newline · esc stop"
            }
            InputDestination::AfterTurn => {
                "enter queues after this turn · ctrl+j newline · esc interrupt"
            }
            InputDestination::SteerCurrentRun if density == surface::Density::Compact => {
                "enter steer · tab queue · esc stop"
            }
            InputDestination::SteerCurrentRun => {
                "enter steer · tab queue · ctrl+j newline · esc interrupt"
            }
            InputDestination::StartTurn => unreachable!("the app is running"),
        }
    } else if app.running && !app.input_lanes.queued().is_empty() {
        if density == surface::Density::Compact {
            "type · esc stop · alt+↑ queued"
        } else {
            "type to steer · alt+↑ edit last queued · esc interrupt"
        }
    } else if app.running {
        if density == surface::Density::Compact {
            "type · esc stop · ctrl+j newline"
        } else {
            "type to steer · tab queues · ctrl+j newline · esc interrupt"
        }
    } else if !text.is_empty() || app.editor.chip_count() > 0 {
        "enter send · ctrl+j newline · ctrl+g edit · alt+backspace remove chip · esc clear"
    } else if density == surface::Density::Compact {
        "/ commands · @ image/file · ctrl+v image · ? help"
    } else {
        "/ commands · @ image/file · ctrl+v image · ! shell · ? help"
    };
    let left = if !app.running && text.is_empty() && app.editor.has_recently_cleared() {
        format!("{left} · ctrl+z restore")
    } else {
        left.to_string()
    };
    let left = format!("{left} · {}", app.mouse_capture.hint());
    let left = clip_text(&left, area.width);
    render_lr_line(f, area, footer_spans(&left, &app.theme), Vec::new());
}

/// Refresh the parsed streaming Markdown document only when its source revision changed. Returns
/// whether a parse occurred, which makes the performance contract directly regression-testable.
pub(super) fn ensure_stream_doc(app: &mut App) -> bool {
    if app.cur_text.trim().is_empty()
        || (app.cur_doc.is_some() && app.cur_doc_revision == app.cur_text_revision)
    {
        return false;
    }
    // Incremental: `cur_text` only ever grows between stream boundaries, and `cur_doc` is dropped at
    // every boundary, so `cur_doc == None` is exactly the "this is a new document" signal and is the
    // one place the settled prefix has to be reset. Re-parsing the whole accumulated answer on every
    // delta batch is quadratic in answer length, which is why long answers visibly slowed down as
    // they streamed.
    if app.cur_doc.is_none() {
        app.cur_doc = Some(crate::markdown::MarkdownDoc {
            blocks: Vec::new(),
            source: None,
        });
        app.cur_doc_parse = crate::markdown::StreamingParse::default();
    }
    let doc = app.cur_doc.as_mut().expect("just ensured a live document");
    app.cur_doc_parse.extend(doc, &app.cur_text);
    app.cur_doc_revision = app.cur_text_revision;
    true
}

/// Where one contiguous run of transcript rows lives while a frame is being laid out. Nothing here
/// owns a copy of the rows: a settled block points at the per-block render cache by id, the animated
/// and streaming pieces point into this frame's `live` arena, and a gap is pure geometry.
pub(super) enum TranscriptRows {
    Blank,
    Live(usize),
    LiveAssistant,
}

/// Copy one already-rendered run's `[from, to)` rows into the frame's viewport buffers. Hyperlink
/// rows are translated into ABSOLUTE transcript coordinates (what `apply_to_buffer` subtracts the
/// scroll from); `row_map` receives one entry per VISIBLE row.
#[allow(clippy::too_many_arguments)]
pub(super) fn push_viewport_rows(
    rendered: &crate::render::RenderedLines,
    block_index: usize,
    segment_start: usize,
    from: usize,
    to: usize,
    lines: &mut Vec<Line<'static>>,
    row_map: &mut Vec<usize>,
    hyperlinks: &mut Vec<crate::render::HyperlinkRegion>,
) {
    for row in from..to {
        lines.push(rendered.lines[row].clone());
        row_map.push(block_index);
    }
    for region in &rendered.hyperlinks {
        if region.row >= from && region.row < to {
            let mut region = region.clone();
            region.row = region.row.saturating_add(segment_start);
            hyperlinks.push(region);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn push_live_markdown_rows(
    layout: &live_markdown::LiveMarkdownLayout,
    theme: &theme::Theme,
    width: u16,
    running: bool,
    caret_on: bool,
    segment_start: usize,
    from: usize,
    to: usize,
    lines: &mut Vec<Line<'static>>,
    row_map: &mut Vec<usize>,
    hyperlinks: &mut Vec<crate::render::HyperlinkRegion>,
) {
    let last = layout.len().saturating_sub(1);
    for row in from..to {
        let Some(mut line) = layout.line(row, theme) else {
            continue;
        };
        if running && caret_on && row == last && crate::render::line_width(&line) < width {
            line.spans
                .push(Span::styled("▋", Style::default().fg(theme.role_assistant)));
        }
        lines.push(line);
        row_map.push(usize::MAX);
    }
    hyperlinks.extend(layout.visible_hyperlinks(from, to, segment_start));
}

/// The largest number of rows the workflow region may ask for on a frame this tall.
///
/// The region is pinned chrome, not the conversation. A fan of forty investigators renders a tree
/// far taller than any terminal, and `Surface::resolve` would hand it everything down to the
/// transcript's one-row floor — so the operator would be watching a workflow with no record of the
/// turn that launched it. Half the frame is the bound; the tree windows into it and reports what it
/// hid, which is a truthful summary rather than a silent clip.
///
/// A zero- or one-row frame yields zero: on a frame that small the composer and the fail-closed
/// decision surface outrank inspection chrome.
pub(super) fn workflow_region_cap(frame_height: u16) -> u16 {
    if frame_height < 2 {
        return 0;
    }
    frame_height.div_ceil(2)
}

pub(super) fn draw(f: &mut Frame, app: &mut App) {
    // Durable workflow inventory is fetched only when `/workflows` is opened. Rendering — including
    // the first frame — is a pure projection and never scans sidecars.
    // A newly arrived capability decision outranks optional inspection chrome. The viewer cannot
    // hide a fail-closed approval surface while the runtime is blocked on it.
    if app.pending.is_some() || app.pending_mcp_input.is_some() {
        if app.transcript_viewer.is_open() {
            app.transcript_viewer.close();
        }
        if app.workflows_panel.is_open() {
            app.workflows_panel.close();
        }
    }
    if app.workflows_panel.is_open() {
        let runs = workflow_panel_runs(app);
        workflows_panel::render(
            f,
            &mut app.workflows_panel,
            &runs,
            &app.session_name,
            &app.theme,
            app.spin,
        );
        return;
    }
    if app.transcript_viewer.is_open() {
        transcript_viewer::render(f, &mut app.transcript_viewer, &app.theme);
        return;
    }
    // The dock grows for multiline input, bounded to six editable rows. A blocking approval asks
    // for the full six-row decision surface; short terminals degrade through Surface::resolve.
    let n_input_rows = if app.pending_mcp_input.is_some() {
        6
    } else {
        (app.editor.text().split('\n').count().clamp(1, 6) as u16)
            .saturating_add(u16::try_from(app.editor.chip_count()).unwrap_or(u16::MAX))
    };
    let blocking_input = app.pending.is_some() || app.pending_mcp_input.is_some();
    let lane_rows = if blocking_input {
        0
    } else {
        u16::from(!app.input_lanes.steers().is_empty())
            + u16::from(!app.input_lanes.queued().is_empty())
    };
    // The status line is stable chrome below the composer, including on the fresh landing. Surface
    // geometry drops it only when a physically tiny frame cannot spare the row.
    let show_status = true;
    // The workflow region asks for its own height. A live script run's tree is drawn HERE, pinned
    // above the composer, and the transcript pass below skips that block, so the tree exists on
    // exactly one surface. Rows are built once and reused: the natural count is the request, and
    // the granted height windows the SAME rows (see `block::window_workflow_rows`). Every region
    // shares the stage's full-width grid (`surface::Surface::resolve`, asserted by
    // `product_widths_keep_one_full_width_body_grid`), so the frame width is the region's width.
    let workflow_rows = app.workflow_region_rows(f.area().width);
    let requested_workflow_rows = u16::try_from(workflow_rows.len())
        .unwrap_or(u16::MAX)
        .min(workflow_region_cap(f.area().height));
    let fresh_landing = !app.running
        && app.pending.is_none()
        && app.transcript.len() == 1
        && matches!(
            app.transcript.first().map(|block| &block.kind),
            Some(block::BlockKind::Welcome { .. })
        );
    let surface = if fresh_landing {
        let landing_width = f.area().width.min(surface::LANDING_MAX_WIDTH);
        let welcome_rows = match landing_width {
            0..=15 => 1,
            16..=27 => 2,
            _ => 6,
        };
        surface::Surface::resolve_landing(f.area(), n_input_rows, welcome_rows, show_status)
    } else {
        surface::Surface::resolve(
            f.area(),
            if blocking_input { 6 } else { n_input_rows },
            lane_rows,
            requested_workflow_rows,
            show_status,
            blocking_input,
        )
    };

    // Which block the transcript must NOT draw, because the region is drawing it. Decided from the
    // GRANTED height rather than the request: a frame too small to spare the region even one row
    // grants zero, and hiding the run from the transcript as well would leave a running workflow
    // rendered nowhere at all. On such a frame the run falls back into the conversation.
    let region_block = (surface.workflow.height > 0)
        .then(|| app.workflow_monitor.region_block())
        .flatten();

    // Reset the complete full-screen frame, then draw only semantic terminal primitives. There is
    // intentionally no desktop canvas, window fill, chrome strip, or card background.
    f.render_widget(ratatui::widgets::Clear, f.area());

    // transcript — each structured block self-renders to ALREADY-WRAPPED rows at `inner_w`
    // (ADR-015 §3), so the concatenation is fed to the exact pre-wrap→scroll-unit math unchanged
    // (the load-bearing R6 invariant). No outer box: a full-width flow with per-block gutters reads
    // far less like a toy than a dense boxed log. All body regions now share one exact grid; the
    // scrollbar owns its own stage-gutter rect. Reserving it before wrapping keeps the indicator
    // from overwriting the final evidence cell when the transcript overflows.
    let inner_w = surface.transcript_content_width();
    if app.render_cache_width != inner_w || app.render_cache_theme_epoch != app.theme_epoch {
        app.render_cache.clear();
        app.render_cache_width = inner_w;
        app.render_cache_theme_epoch = app.theme_epoch;
    }
    // Streaming Markdown is parsed only when provider text changes. Active frames still re-render
    // at 10 fps for the caret/activity animation, but unchanged deltas do not repeatedly rebuild
    // the semantic document.
    ensure_stream_doc(app);
    if !app.cur_text.trim().is_empty() {
        let App {
            live_markdown_layout,
            cur_doc,
            cur_doc_parse,
            cur_text,
            theme,
            theme_epoch,
            hyperlink_policy,
            ..
        } = app;
        live_markdown_layout.update(
            cur_doc
                .as_ref()
                .expect("non-empty streaming text has a parsed document"),
            cur_doc_parse,
            cur_text,
            live_markdown::LiveMarkdownRenderContext {
                width: inner_w,
                theme_epoch: *theme_epoch,
                theme,
                hyperlinks: hyperlink_policy,
            },
        );
    }
    // Rebuild retained block geometry only when its semantic key changes. Ordinary spinner and
    // streaming frames reuse the prefix sums below and locate their viewport with two binary
    // searches; they never walk all 1,200 retained blocks.
    let full_layout_rebuild =
        !app.transcript_layout
            .matches(inner_w, app.theme_epoch, region_block);
    let dirty_from = full_layout_rebuild
        .then_some(0)
        .or(app.transcript_dirty_from);
    if let Some(dirty_from) = dirty_from {
        let mut entries = Vec::new();
        let theme = &app.theme;
        let spin = app.spin;
        let hyperlink_policy = &app.hyperlink_policy;
        let render_cache = &mut app.render_cache;
        let mut previous: Option<&block::BlockKind> = app.transcript[..dirty_from]
            .iter()
            .rev()
            .find(|block| Some(block.id) != region_block)
            .map(|block| &block.kind);
        for (block_index, block) in app.transcript.iter().enumerate().skip(dirty_from) {
            if Some(block.id) == region_block {
                continue;
            }
            if let Some(previous) = previous {
                let gap = usize::from(block::gap_before(previous, &block.kind));
                if gap > 0 {
                    entries.push(transcript_layout::Entry::blank(gap, block_index));
                }
            }
            previous = Some(&block.kind);
            if block.cacheable() {
                if render_cache.get(&block.id).map(|(revision, _)| *revision)
                    != Some(block.revision)
                {
                    let rendered =
                        block.render_with_hyperlinks(inner_w, theme, spin, hyperlink_policy);
                    render_cache.insert(block.id, (block.revision, rendered));
                }
                let rows = render_cache
                    .get(&block.id)
                    .map_or(0, |(_, rendered)| rendered.lines.len());
                entries.push(transcript_layout::Entry::cached(
                    block.id,
                    block_index,
                    rows,
                ));
            } else {
                let rows = block
                    .render_with_hyperlinks(inner_w, theme, spin, hyperlink_policy)
                    .lines
                    .len();
                entries.push(transcript_layout::Entry::live(block_index, rows));
            }
        }
        if full_layout_rebuild {
            app.transcript_layout
                .rebuild(inner_w, app.theme_epoch, region_block, entries);
        } else {
            app.transcript_layout.rebuild_suffix(dirty_from, entries);
        }
        app.transcript_dirty_from = None;
    }

    // The two in-flight projections are not retained transcript blocks. Their plan is bounded to
    // four entries (gap + thinking + gap + answer) and is appended after the indexed geometry.
    let mut live: Vec<crate::render::RenderedLines> = Vec::new();
    let mut tail_plan: Vec<(TranscriptRows, usize, usize)> = Vec::new();
    let retained_rows = app.transcript_layout.total_rows();
    let mut total_rows = retained_rows;
    {
        let theme = &app.theme;
        let spin = app.spin;
        if !app.cur_think.trim().is_empty() {
            if total_rows > 0 {
                tail_plan.push((TranscriptRows::Blank, 1, usize::MAX));
                total_rows += 1;
            }
            let tb = block::Block::new(
                u64::MAX,
                block::BlockKind::Thinking {
                    text: app.cur_think.clone(),
                    open: true,
                },
            );
            let rendered = crate::render::RenderedLines::plain(tb.render(inner_w, theme, spin));
            let count = rendered.lines.len();
            tail_plan.push((TranscriptRows::Live(live.len()), count, usize::MAX));
            live.push(rendered);
            total_rows += count;
        }
        if !app.cur_text.trim().is_empty() {
            if total_rows > 0 {
                tail_plan.push((TranscriptRows::Blank, 1, usize::MAX));
                total_rows += 1;
            }
            let count = app.live_markdown_layout.len();
            tail_plan.push((TranscriptRows::LiveAssistant, count, usize::MAX));
            total_rows += count;
        }
    }
    let total = u16::try_from(total_rows).unwrap_or(u16::MAX); // saturating (review LOW: >65535 rows)
    let view_h = surface.transcript.height;
    let max_scroll = total.saturating_sub(view_h);
    if !app.follow_tail && app.last_view_h > 0 {
        // Preserve the same absolute rendered-row index when append or layout changes the scrollable
        // extent. This is exact for append-only updates and shelf height changes; resize/fold can
        // reflow content at that row, so a future block-id/logical-row anchor is still required.
        // `bottom_offset` may already include a user PageUp/Down delta made since the previous frame.
        let previous_extent = app.last_total_rows.saturating_sub(app.last_view_h);
        if max_scroll >= previous_extent {
            app.bottom_offset = app
                .bottom_offset
                .saturating_add(max_scroll - previous_extent);
        } else {
            app.bottom_offset = app
                .bottom_offset
                .saturating_sub(previous_extent - max_scroll);
        }
    }
    app.last_total_rows = total;
    app.last_view_h = view_h;
    app.bottom_offset = app.bottom_offset.min(max_scroll); // clamp: can't scroll above the top
    if app.bottom_offset == 0 && !app.follow_tail {
        app.follow_latest();
    }
    let scroll = max_scroll - app.bottom_offset;
    // Pass three: materialise the window only. `hyperlink_regions` keeps ABSOLUTE transcript rows —
    // that is the coordinate `apply_to_buffer` subtracts the scroll from — while `row_map` is now
    // viewport-relative, because the hit-test already knows which row the viewport starts at.
    let first_row = usize::from(scroll);
    let last_row = first_row
        .saturating_add(usize::from(view_h))
        .min(total_rows);
    let window = last_row.saturating_sub(first_row);
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(window);
    let mut row_map: Vec<usize> = Vec::with_capacity(window); // block index per VISIBLE row (usize::MAX = spacer/stream)
    let mut hyperlink_regions = Vec::new();
    let retained_visible = app
        .transcript_layout
        .visible_range(first_row, last_row.min(retained_rows));
    for entry_index in retained_visible {
        let Some(entry) = app.transcript_layout.entry(entry_index).copied() else {
            continue;
        };
        let segment_start = app.transcript_layout.row_start(entry_index);
        let segment_end = segment_start.saturating_add(entry.rows);
        let from = first_row.max(segment_start) - segment_start;
        let to = last_row.min(segment_end) - segment_start;
        match entry.source {
            transcript_layout::Source::Blank => {
                for _ in from..to {
                    lines.push(Line::from(""));
                    row_map.push(usize::MAX);
                }
            }
            transcript_layout::Source::Cached(id) => {
                if let Some((_, rendered)) = app.render_cache.get(&id) {
                    push_viewport_rows(
                        rendered,
                        entry.block_index,
                        segment_start,
                        from,
                        to,
                        &mut lines,
                        &mut row_map,
                        &mut hyperlink_regions,
                    );
                }
            }
            transcript_layout::Source::LiveBlock(block_index) => {
                if let Some(block) = app.transcript.get(block_index) {
                    let rendered = block.render_with_hyperlinks(
                        inner_w,
                        &app.theme,
                        app.spin,
                        &app.hyperlink_policy,
                    );
                    push_viewport_rows(
                        &rendered,
                        entry.block_index,
                        segment_start,
                        from,
                        to.min(rendered.lines.len()),
                        &mut lines,
                        &mut row_map,
                        &mut hyperlink_regions,
                    );
                }
            }
        }
    }

    let mut cursor = retained_rows;
    for (rows, count, block_index) in &tail_plan {
        let segment_start = cursor;
        cursor = cursor.saturating_add(*count);
        if cursor <= first_row || segment_start >= last_row {
            continue;
        }
        let from = first_row.max(segment_start) - segment_start;
        let to = last_row.min(cursor) - segment_start;
        match rows {
            TranscriptRows::Blank => {
                for _ in from..to {
                    lines.push(Line::from(""));
                    row_map.push(usize::MAX);
                }
            }
            TranscriptRows::Live(index) => push_viewport_rows(
                &live[*index],
                *block_index,
                segment_start,
                from,
                to,
                &mut lines,
                &mut row_map,
                &mut hyperlink_regions,
            ),
            TranscriptRows::LiveAssistant => push_live_markdown_rows(
                &app.live_markdown_layout,
                &app.theme,
                inner_w,
                app.running,
                (app.spin / 4).is_multiple_of(2),
                segment_start,
                from,
                to,
                &mut lines,
                &mut row_map,
                &mut hyperlink_regions,
            ),
        }
    }
    // stash viewport params for mouse hit-testing (click-to-fold, wheel scroll — R9)
    app.row_map = row_map;
    app.view_top = surface.transcript.y;
    app.view_scroll = scroll;
    app.view_h = view_h;
    let transcript = Paragraph::new(lines); // NO .wrap(): rows == scroll units, and only the window is built
    f.render_widget(transcript, surface.transcript);
    hyperlink::apply_to_buffer(
        f.buffer_mut(),
        surface.transcript,
        scroll,
        &hyperlink_regions,
        &app.hyperlink_policy,
    );

    // Scrollbar in the reserved right column — a position indicator (polish backlog P0). Only when
    // the content overflows the viewport, so a short session stays clean.
    if total > view_h {
        let mut sb_state = ScrollbarState::new(total as usize)
            .position(scroll as usize)
            .viewport_content_length(view_h as usize);
        let sb = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_symbol("█")
            .track_symbol(Some("│"))
            .begin_symbol(None)
            .end_symbol(None)
            // The track is a hairline BEHIND the thumb, so it must be the dimmer of the two.
            // `code_bg` is a background token — `Color::Reset` in the default theme — and using it
            // as a foreground painted the track brighter than the `muted` thumb.
            .thumb_style(Style::default().fg(app.theme.muted))
            .track_style(Style::default().fg(app.theme.border));
        f.render_stateful_widget(sb, surface.scrollbar, &mut sb_state);
    }

    // The workflow region, between the transcript and the queued/steer lanes. On every frame with
    // no live run the height is 0 and this paints nothing — the region is free until it is earned.
    // A granted height smaller than the tree is not a clip: `window_workflow_rows` keeps the totals
    // footer and states how many rows it hid above and below.
    if surface.workflow.height > 0 && !workflow_rows.is_empty() {
        let rows = block::window_workflow_rows(
            workflow_rows,
            usize::from(surface.workflow.height),
            &app.theme,
        );
        f.render_widget(Paragraph::new(rows), surface.workflow);
    }

    render_pending_lanes(f, surface.lanes, app);

    render_composer(f, surface.composer, app);
    render_hint(f, surface.hint, surface.density, app);
    // One permanent footer row: live state on the left, truthful route/effort/context on the right.
    render_status(f, surface.status, surface.density, app);

    // completion popup, overlaid just above the input box. The rect is ALWAYS clamped to the frame
    // (review CRITICAL: an unclamped rect on a short terminal made ratatui's Clear index out of the
    // buffer and panic the whole TUI). Items are WINDOWED around the selection so a selection past
    // the visible rows stays on screen.
    if let Some(comp) = app.completions.view() {
        let rows: Vec<PopupRow> = comp
            .items
            .iter()
            .map(|(name, desc)| PopupRow {
                lead: ui_safe_text(&format!("{}{}", comp.lead, name)),
                lead_accent: true,
                aux: ui_safe_text(desc),
                enabled: true,
            })
            .collect();
        let title = if comp.lead == '@' {
            "files"
        } else {
            "commands"
        };
        render_list_popup(
            f,
            surface.overlay_anchor,
            title,
            &rows,
            comp.sel,
            None,
            &app.theme,
        );
    }

    // Selection picker overlay (R7.a) — the SAME component as the completion menu (TUI v3 §9), so the
    // width, height, border, nav, title grammar and selection bar are identical. Rendered last so it
    // sits above any stray completion.
    if let Some(pk) = &app.picker {
        let visible = pk.visible_indices();
        let rows: Vec<PopupRow> = visible
            .iter()
            .filter_map(|&index| pk.items.get(index).map(|item| (index, item)))
            .map(|(index, it)| {
                let mut aux = String::new();
                if index == pk.sel {
                    let breadcrumb = pk.ancestor_breadcrumb(index);
                    if !breadcrumb.is_empty() {
                        aux.push_str(&breadcrumb);
                    }
                }
                if !it.hint.is_empty() {
                    if !aux.is_empty() {
                        aux.push_str("  ·  ");
                    }
                    aux.push_str(&it.hint);
                }
                if !it.enabled && !it.expandable {
                    if !aux.is_empty() {
                        aux.push_str("  ");
                    }
                    aux.push_str("unavailable: ");
                    aux.push_str(it.disabled_reason.as_deref().unwrap_or("disabled"));
                }
                let disclosure = if it.expandable {
                    if pk.has_query() || it.expanded {
                        "▾ "
                    } else {
                        "▸ "
                    }
                } else if it.parent.is_some() || it.depth > 0 {
                    "  "
                } else {
                    ""
                };
                PopupRow {
                    lead: ui_safe_text(&format!(
                        "{}{}{}{}",
                        "  ".repeat(it.depth.min(32)),
                        disclosure,
                        it.label,
                        if it.is_current { "  current" } else { "" }
                    )),
                    lead_accent: false,
                    aux: ui_safe_text(&aux),
                    // Expansion stays available through picker_key even when account selection is
                    // blocked; rendering keeps the provider header grey so billing/auth state is
                    // visible at the top level, not only on descendant leaves.
                    enabled: it.enabled,
                }
            })
            .collect();
        // Just the title — the modal-title icon zoo (◇◆▷⚿◈, three indistinguishable diamonds) is gone
        // (findings 5); identity is the word, like the tool line.
        render_list_popup(
            f,
            surface.overlay_anchor,
            &ui_safe_text(&pk.title),
            &rows,
            pk.visible_selection(&visible),
            Some(&pk.query),
            &app.theme,
        );
    }
}
