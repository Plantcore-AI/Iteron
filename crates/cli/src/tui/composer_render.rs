//! Approval and composer rendering, pending input lanes and attachment presentation.

use super::{
    App, ApprovalChoice, Block, BorderType, Borders, Color, Frame, InputDestination, Line,
    Modifier, Paragraph, Pending, Rect, Span, Style, approval_operation_text, block,
    cached_input_destination, cap_label, capability_can_be_remembered, clip_spans, clip_text,
    command_token, display_col, mcp_input, one_line_preview, popup_detail_lines, text_width,
    ui_safe_text,
};

/// Drafts carrying chips cannot travel through the text-only steer protocol. A command with chips
/// has a separate refusal affordance below; ordinary attached prose goes to the next-turn lane.
pub(super) fn composer_destination(app: &App) -> InputDestination {
    if app.run.running() && app.editor.chip_count() > 0 {
        InputDestination::AfterTurn
    } else {
        cached_input_destination(
            app.run.running(),
            app.run.interrupting(),
            app.editor.draft_shape(),
        )
    }
}

pub(super) fn composer_command_attachments(app: &App) -> bool {
    app.run.running()
        && app.editor.chip_count() > 0
        && matches!(
            app.editor.draft_shape(),
            crate::editor::DraftShape::Slash { .. } | crate::editor::DraftShape::Shell
        )
}

pub(super) fn render_pending_lanes(f: &mut Frame, area: Rect, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let mut lines = Vec::new();
    let line =
        |label: String, input: &super::input_lanes::PendingInput, suffix: &str, warning: bool| {
            let attachments = input.images.len().saturating_add(input.files.len());
            let preview = if input.text.trim().is_empty() && attachments > 0 {
                format!("{attachments} attachments")
            } else if attachments > 0 {
                format!("{} · {attachments} attachments", ui_safe_text(&input.text))
            } else {
                ui_safe_text(&input.text)
            };
            let suffix = if area.width >= 36 { suffix } else { "" };
            let preview_w = area
                .width
                .saturating_sub(text_width(&label))
                .saturating_sub(text_width(suffix));
            let mut spans = vec![
                Span::styled(
                    label,
                    Style::default().fg(if warning {
                        app.theme.warn
                    } else {
                        app.theme.muted
                    }),
                ),
                Span::styled(
                    one_line_preview(&preview, preview_w),
                    Style::default().fg(app.theme.fg),
                ),
            ];
            let used = super::spans_width(&spans).saturating_add(text_width(suffix));
            if used < area.width {
                spans.push(Span::raw(" ".repeat(usize::from(area.width - used))));
            }
            spans.push(Span::styled(
                suffix.to_string(),
                Style::default().fg(app.theme.muted),
            ));
            Line::from(clip_spans(spans, area.width))
        };
    if let Some(input) = app.input_lanes.held().back() {
        lines.push(line(
            format!("held {} · ", app.input_lanes.held().len()),
            input,
            " · alt+↑ review",
            true,
        ));
    }
    let steers = app.input_lanes.steers().len();
    let queued = app.input_lanes.queued().len();
    if let Some(input) = app.input_lanes.steers().front()
        && (lines.is_empty() || queued == 0)
    {
        lines.push(line(
            format!("steer {steers} · "),
            input,
            " · next safe point",
            false,
        ));
    }
    if let Some(input) = app.input_lanes.queued().front() {
        let label = if !app.input_lanes.held().is_empty() && steers > 0 {
            format!("queued {queued} + {steers} steer · ")
        } else {
            format!("queued {queued} · ")
        };
        let suffix = if app.input_lanes.held().is_empty() {
            " · alt+↑ edit last"
        } else {
            " · after this turn"
        };
        lines.push(line(label, input, suffix, false));
    }
    lines.truncate(usize::from(area.height));
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
        let selected = app.permission_prompt.choice() == choice;
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
            .find(|(choice, _)| *choice == app.permission_prompt.choice())
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
        && let Some(pending) = app.permission_prompt.read()
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
    let line_color = if app.permission_prompt.read().is_some() || app.run.interrupting() {
        app.theme.warn
    } else if !text.is_empty() || attachment_count > 0 || app.run.running() {
        app.theme.accent
    } else {
        app.theme.border
    };
    // Blocking security decisions retain a complete, titled frame. Ordinary composition uses one
    // low-contrast input surface, one semantic left rail, and no redundant title or perimeter.
    let body = if app.permission_prompt.read().is_some() && area.width >= 3 && area.height >= 3 {
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
    } else if app.permission_prompt.read().is_some() || area.width < 6 {
        // The single editable cell is more useful than a decorative rail on a tiny terminal.
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

        if area.height >= 3 {
            let state = if app.is_resume_handoff_draft() {
                "Resume command · copy to a new terminal"
            } else if app
                .run
                .awaiting_composer_admission(app.editor.persistence_revision())
            {
                "Awaiting admission · draft preserved"
            } else if composer_command_attachments(app) {
                "Command unavailable · remove attachments"
            } else if app.run.interrupting()
                && matches!(composer_destination(app), InputDestination::AfterTurn)
            {
                "Stopping · next prompt will queue"
            } else {
                match composer_destination(app) {
                    InputDestination::ImmediateCommand => "Control · enter runs now",
                    InputDestination::AfterTurn => "Next turn · enter queues",
                    InputDestination::SteerCurrentRun => "Steer · enter now · tab queue",
                    InputDestination::StartTurn if is_bash => "Shell command",
                    InputDestination::StartTurn => "Message",
                }
            };
            let state = if attachment_count > 0 {
                format!(
                    "{state} · {attachment_count} attachment{}",
                    if attachment_count == 1 { "" } else { "s" }
                )
            } else {
                state.to_string()
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    clip_text(&state, area.width.saturating_sub(3)),
                    Style::default().fg(app.theme.muted),
                ))),
                Rect::new(
                    area.x.saturating_add(2),
                    area.y,
                    area.width.saturating_sub(3),
                    1,
                ),
            );
        }

        let left = u16::from(area.width >= 2) + u16::from(area.width >= 3);
        let vertical = u16::from(area.height >= 3);
        Rect::new(
            area.x.saturating_add(left),
            area.y.saturating_add(vertical),
            area.width.saturating_sub(left).saturating_sub(1),
            area.height.saturating_sub(vertical.saturating_mul(2)),
        )
    };
    if body.height == 0 || body.width == 0 {
        return;
    }

    if let Some(pending) = app.permission_prompt.read() {
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
            .min(body.height.saturating_sub(1))
            .min(3);
        let chip_area = Rect::new(body.x, body.y, body.width, chip_height);
        let chip_lines = chips
            .iter()
            .enumerate()
            .take(usize::from(chip_height))
            .map(|(index, chip)| {
                if index + 1 == usize::from(chip_height) && chips.len() > usize::from(chip_height) {
                    let remaining = chips.len() - index;
                    return Line::from(Span::styled(
                        clip_text(
                            &format!("{remaining} more attachments · alt+backspace remove last"),
                            chip_area.width,
                        ),
                        Style::default().fg(app.theme.muted),
                    ));
                }
                let mut text = match chip {
                    crate::editor::DraftChip::Image(attachment) => format!(
                        "image #{} {} · {}",
                        attachment.id(),
                        attachment.display_name(),
                        format_attachment_size(attachment.file_bytes())
                    ),
                    crate::editor::DraftChip::File(attachment) => format!(
                        "[{}] {} · {} · {}",
                        attachment.kind().label(),
                        attachment.display_name(),
                        format_attachment_size(attachment.text_bytes()),
                        attachment.digest().get(..8).unwrap_or(attachment.digest())
                    ),
                    crate::editor::DraftChip::Paste(paste) => format!(
                        "paste #{} · {} line{} · {}",
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
    let marker_width = if input_body.width >= 3 { 2 } else { 0 };
    let marker_area = Rect::new(input_body.x, input_body.y, marker_width, input_body.height);
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
        input_body.x.saturating_add(marker_width),
        input_body.y,
        input_body.width.saturating_sub(marker_width),
        input_body.height,
    );
    let (crow, ccol) = app.editor.cursor_row_col();
    let cur_line = text.split('\n').nth(crow).unwrap_or("");
    let cur_disp = display_col(cur_line, ccol);
    let scroll_x = cur_disp.saturating_sub(text_area.width.saturating_sub(1));
    let crow_u16 = u16::try_from(crow).unwrap_or(u16::MAX);
    let scroll_y = crow_u16.saturating_sub(text_area.height.saturating_sub(1));
    if text.is_empty() {
        let placeholder = if app.run.interrupting() {
            "draft the next prompt while stopping".to_string()
        } else if attachment_count > 0 && input_body == body {
            format!("{attachment_count} attachments ready · add a message")
        } else if app.run.running() && attachment_count > 0 {
            "add a message for the next turn".to_string()
        } else if app.run.running() {
            "steer the current run".to_string()
        } else {
            "ask about this codebase or describe a task".to_string()
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                clip_text(&placeholder, text_area.width),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn attachment_overflow_keeps_the_draft_editable_and_truthfully_queues_during_a_run() {
        let mut app = App::new();
        app.run
            .submission_accepted(iteron_protocol::SubmissionId(1), std::time::Instant::now());
        for index in 0..6 {
            app.editor
                .capture_paste(&format!("PRIVATE_PAYLOAD_{index}"))
                .unwrap();
        }
        app.editor.insert_str(" EDITABLE");
        let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();
        terminal
            .draw(|frame| render_composer(frame, frame.area(), &mut app))
            .unwrap();
        let screen = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(screen.contains("Next turn · enter queues"), "{screen}");
        assert!(screen.contains("more attachments"), "{screen}");
        assert!(screen.contains("EDITABLE"), "{screen}");
        assert!(!screen.contains("PRIVATE_PAYLOAD"), "{screen}");
        assert_eq!(app.editor.chip_count(), 6);
    }
}
