//! Dedicated terminal form for 2026 MCP multi-round input.

use super::{
    App, Arc, AtomicBool, Block, BorderType, Borders, Editor, Frame, KeyCode, KeyModifiers, Line,
    Paragraph, Rect, Session, Span, Style, app_server, block, clip_text, display_col,
    request_drain, request_interrupt, ui_safe_text,
};
use std::collections::VecDeque;

struct PendingMcpInput {
    prompt: app_server::McpInputPrompt,
    editor: Editor,
    complete: bool,
}

impl PendingMcpInput {
    fn new(prompt: app_server::McpInputPrompt) -> Self {
        Self {
            prompt,
            editor: Editor::new(),
            complete: true,
        }
    }

    fn answers(&self) -> Result<Vec<(String, serde_json::Value)>, String> {
        if !self.complete {
            return Err(
                "this prompt was redacted; decline or use an authorized complete input surface"
                    .into(),
            );
        }
        let input = self.editor.text();
        if input.len() > iteron_protocol::client_mcp_input::MAX_MCP_INPUT_RESPONSE_BYTES {
            return Err("input response exceeds its byte ceiling".into());
        }
        if input.trim().is_empty() {
            return Err("enter a JSON response or press Esc to decline".into());
        }
        let value: serde_json::Value =
            serde_json::from_str(&input).map_err(|_| "invalid JSON response".to_string())?;
        iteron_protocol::client_mcp_input::response_value_bytes(&value).map_err(str::to_owned)?;
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
                .map_err(|_| "response does not match the requested schema".to_string())?;
        }
        Ok(answers)
    }
}

#[derive(Default)]
pub(super) struct McpInputOwner {
    pending: Option<PendingMcpInput>,
    queued: VecDeque<PendingMcpInput>,
    remote_scope: Option<(iteron_protocol::SessionId, iteron_protocol::RunId)>,
}
impl McpInputOwner {
    pub(super) fn is_waiting(&self) -> bool {
        self.pending.is_some()
    }
    fn enqueue(
        &mut self,
        prompt: app_server::McpInputPrompt,
    ) -> Result<bool, app_server::McpInputPrompt> {
        if self.pending.is_none() {
            self.pending = Some(PendingMcpInput::new(prompt));
            return Ok(true);
        }
        if self.queued.len() >= app_server::mcp_input_capacity().saturating_sub(1) {
            return Err(prompt);
        }
        self.queued.push_back(PendingMcpInput::new(prompt));
        Ok(false)
    }
    fn advance(&mut self, answered_request: u64) -> bool {
        if self
            .pending
            .as_ref()
            .is_none_or(|pending| pending.prompt.request_id != answered_request)
        {
            return false;
        }
        self.pending = self.queued.pop_front();
        true
    }
    pub(super) fn clear(&mut self) {
        self.pending = None;
        self.queued.clear();
        self.remote_scope = None;
    }
}
impl App {
    pub(super) fn enqueue_mcp_input(
        &mut self,
        prompt: app_server::McpInputPrompt,
    ) -> Result<(), app_server::McpInputPrompt> {
        if self.mcp_form.enqueue(prompt)? {
            self.completions.dismiss();
            self.status = "MCP server is waiting for your input".into();
        }
        Ok(())
    }
    pub(super) fn reconcile_mcp_inputs(&mut self, session: &Session) -> bool {
        if !self.mcp_form.is_waiting() {
            return false;
        }
        let Some(snapshot) = session.client.mcp_inputs_snapshot() else {
            return false;
        };
        let Some(selected) = session.client.thread_snapshot_v1() else {
            return false;
        };
        if snapshot.thread_id != selected.thread_id || snapshot.run_id != selected.run_id {
            return false;
        }
        let mut changed = false;
        for closed in &snapshot.closed {
            self.mcp_form
                .queued
                .retain(|pending| pending.prompt.request_id != closed.request_id);
            if self.mcp_form.advance(closed.request_id) {
                self.status = if self.mcp_form.is_waiting() {
                    "MCP server is waiting for your input".into()
                } else {
                    format!("MCP input {:?}", closed.state).to_lowercase()
                };
                changed = true;
            }
        }
        changed
    }
    pub(super) fn clear_mcp_inputs(&mut self) {
        self.mcp_form.clear();
    }
}

impl McpInputOwner {
    pub(super) fn observe_remote(
        &mut self,
        snapshot: &iteron_protocol::client_mcp_input::McpInputsSnapshotV1,
        thread: &iteron_protocol::SessionId,
        run: &iteron_protocol::RunId,
    ) -> Result<(), &'static str> {
        if snapshot.version != 1
            || snapshot.thread_id != *thread
            || snapshot.run_id != *run
            || snapshot.pending.len() > app_server::mcp_input_capacity()
            || snapshot.closed.len() > 64
        {
            return Err("input observation scope or bounds changed");
        }
        let mut ids = std::collections::BTreeSet::new();
        for prompt in &snapshot.pending {
            if !ids.insert(prompt.request_id) || !app_server::mcp_prompt_view_fits(prompt) {
                return Err("input prompt exceeds its finite presentation bounds");
            }
            let mut fields = std::collections::BTreeSet::new();
            for field in &prompt.fields {
                if usize::from(field.field_index) >= prompt.fields.len()
                    || !fields.insert(field.field_index)
                {
                    return Err("input field handles are not the complete requested set");
                }
            }
        }
        let scope = (thread.clone(), run.clone());
        let mut candidates = snapshot
            .pending
            .iter()
            .map(|view| {
                let prompt = app_server::McpInputPrompt {
                    request_id: view.request_id,
                    server: view.server_display.clone(),
                    tool: view.tool_display.clone(),
                    request_state: None,
                    fields: view
                        .fields
                        .iter()
                        .map(|field| app_server::McpInputField {
                            id: field.field_index.to_string(),
                            prompt: field.prompt.clone(),
                            schema: field.schema.clone(),
                        })
                        .collect(),
                };
                let mut pending = PendingMcpInput::new(prompt);
                pending.complete = view.prompt_complete;
                pending
            })
            .collect::<VecDeque<_>>();
        // Every retained request, including a queued form, keeps its immutable schema and
        // completeness. A later snapshot cannot upgrade a redacted request into an approval.
        if self.remote_scope.as_ref() == Some(&scope) {
            for held in self.pending.iter().chain(self.queued.iter()) {
                if let Some(candidate) = candidates
                    .iter()
                    .find(|candidate| candidate.prompt.request_id == held.prompt.request_id)
                    && (held.prompt != candidate.prompt || held.complete != candidate.complete)
                {
                    return Err("pending input metadata changed");
                }
            }
        }
        // Validate immutable metadata before replacing any queued form or its owned draft.
        let retained = if self.remote_scope.as_ref() == Some(&scope) {
            if let Some(current) = &self.pending {
                if let Some(index) = candidates
                    .iter()
                    .position(|candidate| candidate.prompt.request_id == current.prompt.request_id)
                {
                    let candidate = &candidates[index];
                    if current.prompt != candidate.prompt || current.complete != candidate.complete
                    {
                        return Err("pending input metadata changed");
                    }
                    candidates.remove(index);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        if !retained {
            self.pending = candidates.pop_front();
        }
        self.queued = candidates;
        self.remote_scope = Some(scope);
        Ok(())
    }
    pub(super) fn remote_answer(
        &self,
        reject: bool,
    ) -> Result<(u64, iteron_protocol::client_mcp_input::McpInputAnswerV1), String> {
        let pending = self.pending.as_ref().ok_or("no observed input request")?;
        let answer = if reject {
            iteron_protocol::client_mcp_input::McpInputAnswerV1::Reject {}
        } else {
            let values = pending
                .answers()?
                .into_iter()
                .map(|(id, content)| {
                    Ok(iteron_protocol::client_mcp_input::McpInputValueV1 {
                        field_index: id.parse().map_err(|_| "invalid observed field handle")?,
                        content,
                    })
                })
                .collect::<Result<Vec<_>, &str>>()?;
            iteron_protocol::client_mcp_input::McpInputAnswerV1::Approve { values }
        };
        Ok((pending.prompt.request_id, answer))
    }
    pub(super) fn remote_handoff(&mut self, request_id: u64) {
        self.advance(request_id);
    }
}

fn send_answer(app: &mut App, session: &Session, answer: app_server::McpInputAnswer) -> bool {
    let Some(request_id) = app
        .mcp_form
        .pending
        .as_ref()
        .map(|pending| pending.prompt.request_id)
    else {
        return true;
    };
    match session.answer_mcp_input(app_server::McpInputResponse { request_id, answer }) {
        Ok(()) => {
            if app.mcp_form.advance(request_id) {
                app.status = if app.mcp_form.is_waiting() {
                    "MCP server is waiting for your input".into()
                } else {
                    "MCP input sent · tool running".into()
                };
            }
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
        KeyCode::Enter if !ctrl && !alt && !shift => {
            let answers = app
                .mcp_form
                .pending
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
        _ => edit_key(app, code, modifiers),
    }
}
/// Pure form editing shared by local and attached clients; answer delivery stays in their adapters.
pub(super) fn edit_key(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
    let ctrl = modifiers.contains(KeyModifiers::CONTROL);
    let alt = modifiers.contains(KeyModifiers::ALT);
    let shift = modifiers.contains(KeyModifiers::SHIFT);
    match code {
        KeyCode::Enter | KeyCode::Char('j') if ctrl || alt || shift => {
            if active_editor(app).text().len()
                < iteron_protocol::client_mcp_input::MAX_MCP_INPUT_RESPONSE_BYTES
            {
                active_editor(app).newline();
            }
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
        KeyCode::Char(character) if !ctrl && !alt => {
            if active_editor(app)
                .text()
                .len()
                .saturating_add(character.len_utf8())
                <= iteron_protocol::client_mcp_input::MAX_MCP_INPUT_RESPONSE_BYTES
            {
                active_editor(app).insert(character);
            }
        }
        _ => {}
    }
}

pub(super) fn handle_paste(app: &mut App, pasted: &str) {
    if active_editor(app).text().len().saturating_add(pasted.len())
        <= iteron_protocol::client_mcp_input::MAX_MCP_INPUT_RESPONSE_BYTES
    {
        active_editor(app).insert_str(pasted);
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "input paste exceeds its byte ceiling; retained the current response",
        );
    }
}

fn active_editor(app: &mut App) -> &mut Editor {
    &mut app
        .mcp_form
        .pending
        .as_mut()
        .expect("an MCP input event owns the editor")
        .editor
}

pub(super) fn render(f: &mut Frame, area: Rect, app: &mut App) -> bool {
    let Some(pending) = app.mcp_form.pending.as_ref() else {
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
        if !pending.complete {
            lines.push(Line::from(
                "Prompt was redacted · approval unavailable · Esc declines",
            ));
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
    #[test]
    fn private_form_keeps_owned_draft_and_queue_until_exact_accepted_request() {
        let mut owner = McpInputOwner::default();
        let first = pending(vec![field("profile", "name", "string")]).prompt;
        assert_eq!(owner.enqueue(first.clone()), Ok(true));
        owner
            .pending
            .as_mut()
            .unwrap()
            .editor
            .insert_str(r#"{"name":"retained response"}"#);
        for id in 1..app_server::mcp_input_capacity() {
            let mut next = first.clone();
            next.request_id = 100 + id as u64;
            assert_eq!(owner.enqueue(next), Ok(false));
        }
        let mut excess = first.clone();
        excess.request_id = 999;
        assert_eq!(owner.enqueue(excess.clone()), Err(excess));
        assert!(!owner.advance(999));
        assert!(
            owner
                .pending
                .as_ref()
                .unwrap()
                .editor
                .text()
                .contains("retained response")
        );
        assert!(owner.advance(first.request_id));
        if app_server::mcp_input_capacity() > 1 {
            assert_eq!(owner.pending.as_ref().unwrap().prompt.request_id, 101);
            assert!(owner.pending.as_ref().unwrap().editor.text().is_empty());
        } else {
            assert!(!owner.is_waiting());
        }
        owner.clear();
        assert!(!owner.is_waiting());
        assert!(owner.queued.is_empty());
        assert!(!owner.advance(101));
    }
    fn remote_snapshot() -> iteron_protocol::client_mcp_input::McpInputsSnapshotV1 {
        use iteron_protocol::client_mcp_input::{
            McpInputFieldViewV1, McpInputPromptViewV1, McpInputsSnapshotV1,
        };
        McpInputsSnapshotV1 {
            version: 1,
            thread_id: iteron_protocol::SessionId("thread".into()),
            run_id: iteron_protocol::RunId("run".into()),
            revision: 1,
            pending: vec![McpInputPromptViewV1 {
                request_id: 3,
                server_display: "alpha".into(),
                tool_display: "profile".into(),
                fields: vec![McpInputFieldViewV1 {
                    field_index: 0,
                    prompt: "Enter name".into(),
                    schema: serde_json::json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
                }],
                prompt_complete: true,
            }],
            closed: vec![],
            omitted_closed: 0,
        }
    }
    #[test]
    fn remote_form_uses_exact_owner_snapshot_and_retains_response_until_matching_handoff() {
        let mut snapshot = remote_snapshot();
        let mut app = App::new();
        app.mcp_form
            .observe_remote(&snapshot, &snapshot.thread_id, &snapshot.run_id)
            .unwrap();
        handle_paste(&mut app, r#"{"name":"private-form-value"}"#);
        app.mcp_form
            .observe_remote(&snapshot, &snapshot.thread_id, &snapshot.run_id)
            .unwrap();
        let (id, answer) = app.mcp_form.remote_answer(false).unwrap();
        assert_eq!(id, 3);
        let iteron_protocol::client_mcp_input::McpInputAnswerV1::Approve { values } = answer else {
            panic!("approve")
        };
        assert_eq!(values[0].field_index, 0);
        assert_eq!(values[0].content["name"], "private-form-value");
        assert!(app.history.blocks().is_empty());
        assert!(app.editor.text().is_empty());
        app.mcp_form.remote_handoff(999);
        assert!(app.mcp_form.is_waiting());
        let mut forged = snapshot.clone();
        forged.pending[0].fields[0].schema = serde_json::json!({"type":"boolean"});
        assert!(
            app.mcp_form
                .observe_remote(&forged, &snapshot.thread_id, &snapshot.run_id)
                .is_err()
        );
        assert!(
            active_editor(&mut app)
                .text()
                .contains("private-form-value")
        );
        let mut second = snapshot.pending[0].clone();
        second.request_id = 4;
        second.prompt_complete = false;
        snapshot.pending.push(second);
        app.mcp_form
            .observe_remote(&snapshot, &snapshot.thread_id, &snapshot.run_id)
            .unwrap();
        for changed in ["schema", "prompt", "complete"] {
            let mut forged = snapshot.clone();
            match changed {
                "schema" => {
                    forged.pending[1].fields[0].schema = serde_json::json!({"type":"boolean"})
                }
                "prompt" => forged.pending[1].fields[0].prompt = "changed request".into(),
                _ => forged.pending[1].prompt_complete = true,
            }
            assert!(
                app.mcp_form
                    .observe_remote(&forged, &snapshot.thread_id, &snapshot.run_id)
                    .is_err(),
                "queued {changed}"
            );
            assert!(!app.mcp_form.queued.front().unwrap().complete);
            assert!(
                active_editor(&mut app)
                    .text()
                    .contains("private-form-value")
            );
        }
        app.mcp_form.remote_handoff(3);
        assert!(app.mcp_form.is_waiting());
        handle_paste(&mut app, r#"{"name":"hidden-schema"}"#);
        assert!(app.mcp_form.remote_answer(false).is_err());
        assert!(app.mcp_form.remote_answer(true).is_ok());
        app.mcp_form.remote_handoff(4);
        assert!(!app.mcp_form.is_waiting());
    }
    #[test]
    fn remote_form_refuses_foreign_or_unbounded_prompts_before_clone_and_errors_are_content_free() {
        let snapshot = remote_snapshot();
        let mut owner = McpInputOwner::default();
        assert!(
            owner
                .observe_remote(
                    &snapshot,
                    &snapshot.thread_id,
                    &iteron_protocol::RunId("foreign".into())
                )
                .is_err()
        );
        assert!(!owner.is_waiting());
        let mut forged = snapshot.clone();
        forged.pending[0].fields[0].field_index = 1;
        assert!(
            owner
                .observe_remote(&forged, &snapshot.thread_id, &snapshot.run_id)
                .is_err()
        );
        forged = snapshot.clone();
        forged.pending[0].fields[0].schema =
            serde_json::json!({"description":"x".repeat(128*1024+1)});
        assert!(
            owner
                .observe_remote(&forged, &snapshot.thread_id, &snapshot.run_id)
                .is_err()
        );
        let mut pending = pending(vec![field("name", "name", "string")]);
        pending.editor.insert_str("private-invalid-json-secret");
        let error = pending.answers().unwrap_err();
        assert!(!error.contains("private-invalid-json-secret"));
        pending.editor.replace_text(r#"{"name":31415926}"#);
        assert!(!pending.answers().unwrap_err().contains("31415926"));
        let mut app = App::new();
        app.mcp_form
            .observe_remote(&snapshot, &snapshot.thread_id, &snapshot.run_id)
            .unwrap();
        handle_paste(
            &mut app,
            &"x".repeat(iteron_protocol::client_mcp_input::MAX_MCP_INPUT_RESPONSE_BYTES + 1),
        );
        assert!(active_editor(&mut app).text().is_empty());
        edit_key(&mut app, KeyCode::Enter, KeyModifiers::CONTROL);
        assert_eq!(active_editor(&mut app).text(), "\n");
    }
}
