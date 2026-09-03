//! Dedicated terminal form for 2026 MCP multi-round input.

use super::*;

pub(super) struct PendingMcpInput {
    pub(super) prompt: app_server::McpInputPrompt,
    pub(super) editor: Editor,
}

impl PendingMcpInput {
    fn new(prompt: app_server::McpInputPrompt) -> Self {
        Self {
            prompt,
            editor: Editor::new(),
        }
    }

    fn answers(&self) -> Result<Vec<(String, serde_json::Value)>, String> {
        let input = self.editor.text();
        if input.trim().is_empty() {
            return Err("enter a JSON response or press Esc to decline".into());
        }
        let value: serde_json::Value = serde_json::from_str(&input)
            .map_err(|error| format!("invalid JSON response: {error}"))?;
        let answers = if self.prompt.fields.len() == 1 {
            vec![(self.prompt.fields[0].id.clone(), value)]
        } else {
            let object = value.as_object().ok_or_else(|| {
                "multiple MCP questions require a JSON object keyed by request id".to_string()
            })?;
            if object.len() != self.prompt.fields.len()
                || object
                    .keys()
                    .any(|id| !self.prompt.fields.iter().any(|field| field.id == *id))
            {
                return Err(
                    "MCP response keys must exactly match the displayed request ids".into(),
                );
            }
            self.prompt
                .fields
                .iter()
                .map(|field| {
                    object
                        .get(&field.id)
                        .cloned()
                        .map(|value| (field.id.clone(), value))
                        .ok_or_else(|| format!("MCP response omits `{}`", field.id))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        for (id, value) in &answers {
            let field = self
                .prompt
                .fields
                .iter()
                .find(|field| field.id == *id)
                .expect("answer ids came from the pending prompt");
            iteron_mcp::validate_mrtr_input(&field.schema, value)
                .map_err(|error| format!("response for `{id}` is invalid: {error}"))?;
        }
        Ok(answers)
    }
}

impl App {
    pub(super) fn enqueue_mcp_input(
        &mut self,
        prompt: app_server::McpInputPrompt,
    ) -> Result<(), app_server::McpInputPrompt> {
        if self.pending_mcp_input.is_none() {
            self.pending_mcp_input = Some(PendingMcpInput::new(prompt));
            self.completion = None;
            self.status = "MCP server is waiting for your input".into();
            return Ok(());
        }
        if self.queued_mcp_inputs.len() >= app_server::MCP_INPUT_CAPACITY.saturating_sub(1) {
            return Err(prompt);
        }
        self.queued_mcp_inputs.push_back(prompt);
        Ok(())
    }

    fn advance_mcp_input(&mut self) {
        self.pending_mcp_input = self.queued_mcp_inputs.pop_front().map(PendingMcpInput::new);
        self.status = if self.pending_mcp_input.is_some() {
            "MCP server is waiting for your input".into()
        } else {
            "MCP input sent · tool running".into()
        };
    }

    pub(super) fn clear_mcp_inputs(&mut self) {
        self.pending_mcp_input = None;
        self.queued_mcp_inputs.clear();
    }
}

fn send_answer(app: &mut App, session: &Session, answer: app_server::McpInputAnswer) -> bool {
    let Some(request_id) = app
        .pending_mcp_input
        .as_ref()
        .map(|pending| pending.prompt.request_id)
    else {
        return true;
    };
    match session.answer_mcp_input(app_server::McpInputResponse { request_id, answer }) {
        Ok(()) => {
            app.advance_mcp_input();
            true
        }
        Err(error) => {
            app.note(block::NoticeLevel::Err, error);
            false
        }
    }
}

pub(super) fn handle_key(
    app: &mut App,
    session: &Session,
    code: KeyCode,
    modifiers: KeyModifiers,
    interrupt: &Arc<AtomicBool>,
    drain: &Arc<AtomicBool>,
    drain_available: bool,
) {
    let ctrl = modifiers.contains(KeyModifiers::CONTROL);
    let alt = modifiers.contains(KeyModifiers::ALT);
    let shift = modifiers.contains(KeyModifiers::SHIFT);
    match code {
        KeyCode::Esc => {
            if send_answer(app, session, app_server::McpInputAnswer::Reject) {
                app.note(block::NoticeLevel::Warn, "MCP input declined");
            }
        }
        KeyCode::Char('c') if ctrl => {
            if send_answer(app, session, app_server::McpInputAnswer::Reject) {
                request_interrupt(app, session, interrupt);
                app.note(
                    block::NoticeLevel::Warn,
                    "MCP input declined · interrupting the current run",
                );
            }
        }
        KeyCode::Char('d') if ctrl => {
            if send_answer(app, session, app_server::McpInputAnswer::Reject) {
                request_drain(app, session, drain, drain_available);
            }
        }
        KeyCode::Enter if !alt && !shift => {
            let answers = app
                .pending_mcp_input
                .as_ref()
                .expect("the MCP form owns this key")
                .answers();
            match answers {
                Ok(answers) => {
                    if send_answer(app, session, app_server::McpInputAnswer::Approve(answers)) {
                        app.note(block::NoticeLevel::Ok, "MCP input accepted");
                    }
                }
                Err(error) => app.note(block::NoticeLevel::Warn, error),
            }
        }
        KeyCode::Enter | KeyCode::Char('j') if ctrl || alt || shift => {
            app.pending_mcp_input
                .as_mut()
                .expect("the MCP form owns this key")
                .editor
                .newline();
        }
        KeyCode::Left if alt => active_editor(app).word_left(),
        KeyCode::Right if alt => active_editor(app).word_right(),
        KeyCode::Char('b') if alt => active_editor(app).word_left(),
        KeyCode::Char('f') if alt => active_editor(app).word_right(),
        KeyCode::Left => active_editor(app).left(),
        KeyCode::Right => active_editor(app).right(),
        KeyCode::Home | KeyCode::Char('a') if code == KeyCode::Home || ctrl => {
            active_editor(app).home();
        }
        KeyCode::End | KeyCode::Char('e') if code == KeyCode::End || ctrl => {
            active_editor(app).end();
        }
        KeyCode::Char('u') if ctrl => active_editor(app).kill_to_start(),
        KeyCode::Char('k') if ctrl => active_editor(app).kill_to_end(),
        KeyCode::Char('w') if ctrl => active_editor(app).delete_word_before(),
        KeyCode::Delete => active_editor(app).delete(),
        KeyCode::Backspace => active_editor(app).backspace(),
        KeyCode::Char(character) if !ctrl && !alt => active_editor(app).insert(character),
        _ => {}
    }
}

pub(super) fn handle_paste(app: &mut App, pasted: &str) {
    active_editor(app).insert_str(pasted);
}

fn active_editor(app: &mut App) -> &mut Editor {
    &mut app
        .pending_mcp_input
        .as_mut()
        .expect("an MCP input event owns the editor")
        .editor
}

pub(super) fn render(f: &mut Frame, area: Rect, app: &mut App) -> bool {
    let Some(pending) = app.pending_mcp_input.as_ref() else {
        return false;
    };
    if area.width == 0 || area.height == 0 {
        return true;
    }
    if area.height == 1 {
        f.render_widget(
            Paragraph::new(clip_text("MCP input required · Esc declines", area.width)),
            area,
        );
        return true;
    }
    let border = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(app.theme.warn))
        .title(format!(
            " {} ",
            clip_text(
                &format!(
                    "MCP input · {}/{}",
                    pending.prompt.server, pending.prompt.tool
                ),
                area.width.saturating_sub(4),
            )
        ));
    let body = border.inner(area);
    f.render_widget(border, area);
    if body.height == 0 {
        return true;
    }
    let editor_rows = u16::try_from(pending.editor.text().split('\n').count())
        .unwrap_or(u16::MAX)
        .clamp(1, body.height);
    let detail_rows = body.height.saturating_sub(editor_rows);
    if detail_rows > 0 {
        let mut lines = Vec::new();
        if let Some(state) = &pending.prompt.request_state {
            lines.push(Line::from(Span::styled(
                clip_text(&format!("state {state}"), body.width),
                Style::default().fg(app.theme.muted),
            )));
        }
        for field in &pending.prompt.fields {
            let schema = serde_json::to_string(&field.schema).unwrap_or_else(|_| "{}".into());
            lines.push(Line::from(Span::styled(
                clip_text(
                    &ui_safe_text(&format!("{} · {} · {schema}", field.id, field.prompt)),
                    body.width,
                ),
                Style::default().fg(app.theme.fg),
            )));
        }
        f.render_widget(
            Paragraph::new(lines),
            Rect::new(body.x, body.y, body.width, detail_rows),
        );
    }
    let input_area = Rect::new(
        body.x,
        body.y.saturating_add(detail_rows),
        body.width,
        editor_rows,
    );
    let text = pending.editor.text();
    let display = if text.is_empty() {
        "JSON response".to_string()
    } else {
        text.clone()
    };
    let style = if text.is_empty() {
        Style::default().fg(app.theme.muted)
    } else {
        Style::default().fg(app.theme.fg)
    };
    let (row, col) = pending.editor.cursor_row_col();
    let row_u16 = u16::try_from(row).unwrap_or(u16::MAX);
    let scroll_y = row_u16.saturating_sub(input_area.height.saturating_sub(1));
    let current = text.split('\n').nth(row).unwrap_or("");
    let display_col = display_col(current, col);
    let scroll_x = display_col.saturating_sub(input_area.width.saturating_sub(1));
    f.render_widget(
        Paragraph::new(
            display
                .split('\n')
                .map(|line| Line::from(Span::styled(line.to_owned(), style)))
                .collect::<Vec<_>>(),
        )
        .scroll((scroll_y, scroll_x)),
        input_area,
    );
    let cursor_x = input_area
        .x
        .saturating_add(display_col.saturating_sub(scroll_x));
    let cursor_y = input_area
        .y
        .saturating_add(row_u16.saturating_sub(scroll_y));
    if cursor_x < input_area.right() && cursor_y < input_area.bottom() {
        f.set_cursor_position((cursor_x, cursor_y));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(id: &str, property: &str, kind: &str) -> app_server::McpInputField {
        app_server::McpInputField {
            id: id.into(),
            prompt: format!("Enter {property}"),
            schema: serde_json::json!({
                "type":"object",
                "properties":{property:{"type":kind}},
                "required":[property]
            }),
        }
    }

    fn pending(fields: Vec<app_server::McpInputField>) -> PendingMcpInput {
        PendingMcpInput::new(app_server::McpInputPrompt {
            request_id: 4,
            server: "alpha".into(),
            tool: "profile".into(),
            request_state: Some("round-1".into()),
            fields,
        })
    }

    #[test]
    fn single_request_accepts_direct_json_only_when_it_matches_the_schema() {
        let mut pending = pending(vec![field("profile", "name", "string")]);
        pending.editor.insert_str(r#"{"name":7}"#);
        assert!(pending.answers().is_err());
        pending.editor.replace_text(r#"{"name":"Alice"}"#);
        assert_eq!(
            pending.answers().unwrap(),
            vec![("profile".into(), serde_json::json!({"name":"Alice"}))]
        );
    }

    #[test]
    fn multiple_requests_require_the_exact_outer_request_ids() {
        let mut pending = pending(vec![
            field("profile", "name", "string"),
            field("confirm", "ok", "boolean"),
        ]);
        pending.editor.insert_str(r#"{"profile":{"name":"Alice"}}"#);
        assert!(pending.answers().is_err());
        pending
            .editor
            .replace_text(r#"{"profile":{"name":"Alice"},"confirm":{"ok":true}}"#);
        assert_eq!(pending.answers().unwrap().len(), 2);
    }
}
