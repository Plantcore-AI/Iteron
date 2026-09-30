//! Approval and composer rendering, pending input lanes and attachment presentation.

use super::{
    App, ApprovalChoice, Block, BorderType, Borders, Color, Frame, Line, Modifier, Paragraph,
    Pending, Rect, Span, Style, approval_operation_text, block, cap_label,
    capability_can_be_remembered, clip_spans, clip_text, command_token, display_col, mcp_input,
    one_line_preview, popup_detail_lines, text_width, ui_safe_text,
};

pub(super) fn render_pending_lanes(f: &mut Frame, area: Rect, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let mut lines = Vec::new();
    let label_w = if area.width >= 72 { 19 } else { 9 };
    if let Some(input) = app.input_lanes.steers().front() {
        let label = if area.width >= 72 {
            "  next safe point  "
        } else {
            "  steer  "
        };
        let suffix = app
            .input_lanes
            .steers()
            .len()
            .checked_sub(1)
            .filter(|count| *count > 0)
            .map(|count| format!("  +{count}"))
            .unwrap_or_default();
        let preview_w = area
            .width
            .saturating_sub(label_w)
            .saturating_sub(text_width(&suffix));
        lines.push(Line::from(vec![
            Span::styled(label, Style::default().fg(app.theme.accent)),
            Span::styled(
                one_line_preview(&ui_safe_text(&input.text), preview_w),
                Style::default().fg(app.theme.fg),
            ),
            Span::styled(suffix, Style::default().fg(app.theme.muted)),
        ]));
    }
    if let Some(input) = app.input_lanes.queued().front() {
        let label = if area.width >= 72 {
            "  after this turn  "
        } else {
            "  queued "
        };
        let suffix = app
            .input_lanes
            .queued()
            .len()
            .checked_sub(1)
            .filter(|count| *count > 0)
            .map(|count| format!("  +{count}"))
            .unwrap_or_default();
        let preview_w = area
            .width
            .saturating_sub(label_w)
            .saturating_sub(text_width(&suffix));
        lines.push(Line::from(vec![
            Span::styled(label, Style::default().fg(app.theme.muted)),
            Span::styled(
                one_line_preview(&ui_safe_text(&input.text), preview_w),
                Style::default().fg(app.theme.fg),
            ),
            Span::styled(suffix, Style::default().fg(app.theme.muted)),
        ]));
    }
    lines.truncate(area.height as usize);
    f.render_widget(Paragraph::new(lines), area);
}

pub(super) fn approval_action_line(app: &App, pending: &Pending, width: u16) -> Line<'static> {
    let rememberable = capability_can_be_remembered(pending.cap);
    let choices: Vec<(ApprovalChoice, String)> = if !pending.prompt_complete {
        vec![(ApprovalChoice::Deny, "[n] Deny · prompt truncated".into())]
    } else if width >= 60 {
        let mut choices = vec![(ApprovalChoice::Once, "[y] Allow once".into())];
        if rememberable {
            choices.push((
                ApprovalChoice::Session,
                format!("[a] Allow {} this session", cap_label(pending.cap)),
            ));
        }
        choices.push((ApprovalChoice::Deny, "[n] Deny".into()));
        choices
    } else if width >= 24 {
        let mut choices = vec![(ApprovalChoice::Once, "[y] once".into())];
        if rememberable {
            choices.push((ApprovalChoice::Session, "[a] session".into()));
        }
        choices.push((ApprovalChoice::Deny, "[n] deny".into()));
        choices
    } else {
        let mut choices = vec![(ApprovalChoice::Once, "[y]".into())];
        if rememberable {
            choices.push((ApprovalChoice::Session, "[a]".into()));
        }
        choices.push((ApprovalChoice::Deny, "[n]".into()));
        choices
    };
    let choice_style = |choice: ApprovalChoice| {
        let selected = app.approval_choice == choice;
        if selected && app.theme.mono {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else if selected {
            Style::default()
                .fg(app.theme.on_accent)
                .bg(app.theme.accent)
                .add_modifier(Modifier::BOLD)
        } else if choice == ApprovalChoice::Deny {
            Style::default().fg(app.theme.error)
        } else {
            Style::default().fg(app.theme.fg)
        }
    };
    let separator = if width < 24 { " " } else { "  " };
    let required = choices
        .iter()
        .map(|(_, label)| text_width(label))
        .fold(0u16, u16::saturating_add)
        .saturating_add(
            text_width(separator)
                .saturating_mul(u16::try_from(choices.len().saturating_sub(1)).unwrap_or(u16::MAX)),
        );
    if required > width
        && let Some((choice, label)) = choices
            .iter()
            .find(|(choice, _)| *choice == app.approval_choice)
    {
        // This is an intentional one-slot pager, not a reordered button row: arrow navigation changes
        // the focused label in place, while the canonical y → a → n order returns as soon as it fits.
        let mut spans = vec![Span::styled(label.clone(), choice_style(*choice))];
        let remaining = width.saturating_sub(text_width(label));
        if remaining >= 3 {
            spans.push(Span::styled(" <>", Style::default().fg(app.theme.muted)));
        }
        return Line::from(spans);
    }
    let mut spans = Vec::new();
    for (index, (choice, label)) in choices.into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(
                separator,
                Style::default().fg(app.theme.faint),
            ));
        }
        spans.push(Span::styled(label, choice_style(choice)));
    }
    Line::from(spans)
}

pub(super) fn render_composer(f: &mut Frame, area: Rect, app: &mut App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    if mcp_input::render(f, area, app) {
        return;
    }
    if area.height == 1
        && let Some(pending) = &app.pending
    {
        // At the physical minimum, fail-closed choice visibility outranks title and transcript.
        f.render_widget(
            Paragraph::new(approval_action_line(app, pending, area.width)),
            area,
        );
        return;
    }
    let text = app.editor.text();
    let attachment_count = app.editor.chip_count();
    let is_bash = text.starts_with('!');
    let line_color = if app.pending.is_some() {
        app.theme.warn
    } else if !text.is_empty() || attachment_count > 0 || app.running {
        app.theme.accent
    } else {
        app.theme.border
    };
    // Blocking security decisions retain a complete, titled frame. Ordinary composition uses one
    // low-contrast input surface, one semantic left rail, and no redundant title or perimeter.
    let body = if app.pending.is_some() && area.width >= 3 && area.height >= 3 {
        let approval = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(line_color))
            .title(format!(
                " {} ",
                clip_text("Permission required", area.width.saturating_sub(4))
            ));
        let inner = approval.inner(area);
        f.render_widget(approval, area);
        inner
    } else if app.pending.is_some() {
        area
    } else {
        let surface_style = if app.theme.mono {
            Style::default()
        } else {
            Style::default().fg(app.theme.user_fg).bg(app.theme.user_bg)
        };
        f.render_widget(Block::default().style(surface_style), area);

        let rail_glyph = if app.theme.mono { "┃" } else { "▌" };
        let rail_style = Style::default()
            .fg(line_color)
            .bg(if app.theme.mono {
                Color::Reset
            } else {
                app.theme.user_bg
            })
            .add_modifier(Modifier::BOLD);
        let rail = (0..area.height)
            .map(|_| Line::from(Span::styled(rail_glyph, rail_style)))
            .collect::<Vec<_>>();
        f.render_widget(
            Paragraph::new(rail),
            Rect::new(area.x, area.y, area.width.min(1), area.height),
        );

        let left = u16::from(area.width >= 2) + u16::from(area.width >= 3);
        let vertical = u16::from(area.height >= 3);
        Rect::new(
            area.x.saturating_add(left),
            area.y.saturating_add(vertical),
            area.width.saturating_sub(left).saturating_sub(1),
            area.height.saturating_sub(vertical.saturating_mul(2)),
        )
    };
    if body.height == 0 {
        return;
    }

    if let Some(pending) = &app.pending {
        let verb = block::verb_for(&pending.tool);
        let title = clip_text(
            &format!("Allow {verb}? · {}", cap_label(pending.cap)),
            body.width,
        );
        let operation = approval_operation_text(pending);
        let title_line = Line::from(Span::styled(
            title,
            Style::default()
                .fg(app.theme.fg)
                .add_modifier(Modifier::BOLD),
        ));
        let operation_style = Style::default().fg(app.theme.fg);
        let mut operation_lines = popup_detail_lines(
            &format!("› {operation}"),
            body.width,
            if body.height >= 6 { 2 } else { 1 },
            operation_style,
        );
        if operation_lines.is_empty() {
            operation_lines.push(Line::from(Span::styled(
                "› operation unavailable",
                operation_style,
            )));
        }
        let mut workspace_spans = vec![Span::styled(
            "workspace ",
            Style::default().fg(app.theme.muted),
        )];
        workspace_spans.extend(crate::semantic_text::spans(
            &pending.workspace,
            crate::semantic_text::Tone::Muted,
            &app.theme,
        ));
        let workspace_line = Line::from(clip_spans(workspace_spans, body.width));
        let reason_line = Line::from(clip_spans(
            crate::semantic_text::spans(
                &pending.reason,
                crate::semantic_text::Tone::Muted,
                &app.theme,
            ),
            body.width,
        ));
        let choice_line = approval_action_line(app, pending, body.width);
        // Security action is the last thing allowed to disappear. The exact operation outranks
        // explanatory prose, so even a two-row body shows operation + allow/deny.
        let mut lines = match body.height {
            0 => Vec::new(),
            1 => vec![choice_line.clone()],
            2 => vec![operation_lines.remove(0), choice_line.clone()],
            3 => vec![
                title_line.clone(),
                operation_lines.remove(0),
                choice_line.clone(),
            ],
            4 => vec![
                title_line.clone(),
                operation_lines.remove(0),
                reason_line.clone(),
                choice_line.clone(),
            ],
            _ => {
                let mut rows = vec![title_line.clone()];
                rows.append(&mut operation_lines);
                rows.push(workspace_line.clone());
                rows.push(reason_line.clone());
                rows.push(choice_line.clone());
                rows
            }
        };
        if lines.len() > body.height as usize {
            let choice = lines.pop().unwrap_or(choice_line);
            lines.truncate(body.height.saturating_sub(1) as usize);
            lines.push(choice);
        }
        f.render_widget(Paragraph::new(lines), body);
        return;
    }

    let input_body = if attachment_count > 0 && body.height > 0 {
        let chips = app.editor.chips();
        let chip_height = u16::try_from(chips.len())
            .unwrap_or(u16::MAX)
            .min(body.height);
        let chip_area = Rect::new(body.x, body.y, body.width, chip_height);
        let chip_lines = chips
            .iter()
            .enumerate()
            .map(|(index, chip)| {
                let mut text = match chip {
                    crate::editor::DraftChip::Image(attachment) => format!(
                        "▧ #{} {} · {}",
                        attachment.id(),
                        attachment.display_name(),
                        format_attachment_size(attachment.file_bytes())
                    ),
                    crate::editor::DraftChip::File(attachment) => format!(
                        "{} [{}] {} · {} · {}",
                        attachment.kind().glyph(),
                        attachment.kind().label(),
                        attachment.display_name(),
                        format_attachment_size(attachment.text_bytes()),
                        attachment.digest().get(..8).unwrap_or(attachment.digest())
                    ),
                    crate::editor::DraftChip::Paste(paste) => format!(
                        "▥ #{} held paste · {} line{} · {}",
                        paste.id(),
                        paste.lines() + 1,
                        if paste.lines() == 0 { "" } else { "s" },
                        format_attachment_size(paste.bytes())
                    ),
                };
                if index + 1 == chips.len() && body.width >= 36 {
                    text.push_str(" · alt+backspace removes last");
                }
                Line::from(clip_spans(
                    crate::semantic_text::spans(
                        &text,
                        crate::semantic_text::Tone::Muted,
                        &app.theme,
                    ),
                    chip_area.width,
                ))
            })
            .collect::<Vec<_>>();
        f.render_widget(Paragraph::new(chip_lines), chip_area);
        Rect::new(
            body.x,
            body.y.saturating_add(chip_height),
            body.width,
            body.height.saturating_sub(chip_height),
        )
    } else {
        body
    };
    if input_body.height == 0 {
        return;
    }

    let marker_color = if is_bash {
        app.theme.warn
    } else {
        app.theme.accent
    };
    let marker = if is_bash { "! " } else { "› " };
    let marker_area = Rect::new(
        input_body.x,
        input_body.y,
        input_body.width.min(2),
        input_body.height,
    );
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            marker,
            Style::default()
                .fg(marker_color)
                .add_modifier(Modifier::BOLD),
        ))),
        marker_area,
    );
    let text_area = Rect::new(
        input_body.x.saturating_add(2),
        input_body.y,
        input_body.width.saturating_sub(2),
        input_body.height,
    );
    let (crow, ccol) = app.editor.cursor_row_col();
    let cur_line = text.split('\n').nth(crow).unwrap_or("");
    let cur_disp = display_col(cur_line, ccol);
    let scroll_x = cur_disp.saturating_sub(text_area.width.saturating_sub(1));
    let crow_u16 = u16::try_from(crow).unwrap_or(u16::MAX);
    let scroll_y = crow_u16.saturating_sub(text_area.height.saturating_sub(1));
    if text.is_empty() {
        let placeholder = if app.running {
            "steer the current run"
        } else {
            "ask about this codebase or describe a task"
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                clip_text(placeholder, text_area.width),
                Style::default().fg(app.theme.muted),
            ))),
            text_area,
        );
    } else {
        let base = Style::default().fg(app.theme.fg);
        let lines: Vec<Line> = text
            .split('\n')
            .enumerate()
            .map(|(index, line)| {
                if index == 0
                    && let Some((token, rest, color)) = command_token(line, &app.theme)
                {
                    return Line::from(vec![
                        Span::styled(
                            token,
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(rest, base),
                    ]);
                }
                Line::from(Span::styled(line.to_string(), base))
            })
            .collect();
        f.render_widget(
            Paragraph::new(lines).scroll((scroll_y, scroll_x)),
            text_area,
        );
    }
    let cursor_x = text_area
        .x
        .saturating_add(cur_disp.saturating_sub(scroll_x));
    let cursor_y = text_area
        .y
        .saturating_add(crow_u16.saturating_sub(scroll_y));
    if !app.pickers.is_open() && cursor_x < text_area.right() && cursor_y < text_area.bottom() {
        f.set_cursor_position((cursor_x, cursor_y));
    }
}

pub(super) fn format_attachment_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    }
}
