//! Explicit re-attach presentation. The service process owns every runtime and physical task.
//! Returning, losing a socket or dropping this UI never submits drain/stop or owns a server handle.
use super::{
    App, block, draw, notification,
    product_projection::ProductProjection,
    remote_transport::Transport,
    terminal_input::{ReadResult, TerminalInput},
    terminal_lifecycle::TermGuard,
    theme, ui_safe_text,
};
use anyhow::{Context, Result, bail};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use iteron_protocol::{
    SubmissionId, SubmissionLifecycleState,
    product_contract::{ProductEventsPageV1, ThreadSnapshotV1, TurnStateV1},
    resident_service::{RESIDENT_SERVICE_VERSION, ResidentServiceViewV1},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
const MAX_DRAFT_BYTES: usize = 64 * 1024;
const MAX_PENDING_COMMANDS: usize = 8;
const POLL_PERIOD: Duration = Duration::from_millis(250);
const REPLY_DEADLINE: Duration = Duration::from_secs(5);

struct Input {
    receiver: mpsc::Receiver<std::io::Result<ReadResult>>,
    stop: Arc<AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
}
impl Input {
    fn start() -> Self {
        let (sender, receiver) = mpsc::channel(32);
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let task = std::thread::spawn(move || {
            let mut input = TerminalInput::default();
            while !done.load(Ordering::Acquire) {
                match input.read(Duration::from_millis(50)) {
                    Ok(Some(event)) => {
                        if sender.blocking_send(Ok(event)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = sender.blocking_send(Err(error));
                        break;
                    }
                }
            }
        });
        Self {
            receiver,
            stop,
            task: Some(task),
        }
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        self.receiver.close();
        self.stop.store(true, Ordering::Release);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}
enum Kind {
    Snapshot,
    Events,
    Submit {
        draft: String,
        revision: u64,
    },
    Control,
    ScopedControl {
        run: iteron_protocol::RunId,
    },
    Approval {
        prompt: SubmissionId,
    },
    Models,
    FinalEvidence {
        run: iteron_protocol::RunId,
    },
    Sessions {
        run: iteron_protocol::RunId,
        generation: u64,
        append: bool,
    },
    SessionsRepair {
        run: iteron_protocol::RunId,
        generation: u64,
    },
    SessionsActivity {
        run: iteron_protocol::RunId,
        generation: u64,
    },
    SessionsChanges {
        run: iteron_protocol::RunId,
        generation: u64,
    },
    Refusals {
        run: iteron_protocol::RunId,
    },
    Inputs,
    McpResponse {
        request_id: u64,
        run: iteron_protocol::RunId,
    },
    ArtifactList {
        prefix: String,
        run: iteron_protocol::RunId,
    },
    ArtifactChunk {
        generation: u64,
    },
    Stop,
}
struct AcceptedDraft {
    id: SubmissionId,
    draft: String,
    revision: u64,
}
struct Request {
    id: u64,
    kind: Kind,
    deadline: Instant,
}
struct View {
    service: ResidentServiceViewV1,
    snapshot: Option<ThreadSnapshotV1>,
    product: ProductProjection,
    pending: Option<Request>,
    queued: std::collections::VecDeque<(Value, Kind)>,
    models: Option<Value>,
    sessions: super::remote_sessions::Sessions,
    product_cursor: u64,
    poll_events: bool,
    poll_inputs: bool,
    last_terminal: Option<(
        iteron_protocol::RunId,
        iteron_protocol::product_contract::ProductTurnId,
        u64,
    )>,
    final_needed: bool,
    last_live_seq: u64,
    accepted: Option<AcceptedDraft>,
    expected_submission: Option<SubmissionId>,
    artifact: Option<(iteron_protocol::RunId, super::artifact_view::Transfer)>,
}
impl View {
    fn scope(&self) -> Value {
        json!({"thread_id":self.service.scope.thread_id,"run_id":self.service.current_run_id})
    }
    fn queue(&mut self, control: Value, kind: Kind) -> Result<()> {
        if self.queued.len() >= MAX_PENDING_COMMANDS {
            bail!("remote control queue is busy; draft retained");
        }
        self.queued.push_back((control, kind));
        Ok(())
    }
    fn product(&mut self, command: Value, kind: Kind) -> Result<()> {
        self.queue(json!({"type":"product_v1","command":command}), kind)
    }
    fn snapshot_request(&mut self) -> Result<()> {
        self.product(
            json!({"type":"thread_read","thread_id":self.service.scope.thread_id}),
            Kind::Snapshot,
        )
    }
    fn events_request(&mut self) -> Result<()> {
        self.product(json!({"type":"events_read","thread_id":self.service.scope.thread_id,"after":self.product_cursor}),Kind::Events)
    }
    fn inputs_request(&mut self) -> Result<()> {
        self.queue(json!({"type":"mcp_inputs_v1","command":{"thread_id":self.service.scope.thread_id,"run_id":self.service.current_run_id,"command":{"action":"read"}}}),Kind::Inputs)
    }
    fn final_request(&mut self) -> Result<()> {
        self.queue(json!({"type":"host_final_evidence_v1","command":{"thread_id":self.service.scope.thread_id,"run_id":self.service.current_run_id}}),Kind::FinalEvidence{run:self.service.current_run_id.clone()})
    }
    fn sessions_request(
        &mut self,
        cursor: Option<String>,
        generation: u64,
        append: bool,
    ) -> Result<()> {
        self.queue(
            json!({"type":"thread_lifecycle_v1","command":{"type":"list","cursor":cursor,"limit":super::session_picker::session_picker_page_size()}}),
            Kind::Sessions { run: self.service.current_run_id.clone(), generation, append },
        )
    }
    fn sessions_key(&mut self, app: &mut App, key: crossterm::event::KeyEvent) -> Result<bool> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('d') {
            return Ok(true);
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.sessions.clear(app);
            return self.interrupt().map(|()| false);
        }
        if let Some(update) = app.pickers.key(key.code, key.modifiers) {
            match update.event {
                super::picker::PickerEvent::Accept(super::picker::PickAction::AdoptRun(run)) => {
                    self.sessions.clear(app);
                    self.queue(
                        json!({"type":"session_navigate_v1","command":{"action":"resume","thread_id":self.service.scope.thread_id,"run_id":self.service.current_run_id,"target_run_id":run}}),
                        Kind::Control,
                    )?;
                }
                super::picker::PickerEvent::Cancel => self.sessions.clear(app),
                _ => {}
            }
        }
        Ok(false)
    }
    fn sessions_poll(&mut self, app: &App) -> Result<bool> {
        if self.pending.is_some() || !self.queued.is_empty() {
            return Ok(false);
        }
        if let Some(cursor) = self.sessions.next_page(app) {
            self.sessions_request(Some(cursor), self.sessions.generation(), true)?;
            return Ok(true);
        }
        if self.sessions.activity_due(app) && self.snapshot.is_some() {
            self.queue(
                json!({"type":"activity_center_v1","command":{"action":"list","thread_id":self.service.scope.thread_id,"run_id":self.service.current_run_id}}),
                Kind::SessionsActivity { run: self.service.current_run_id.clone(), generation: self.sessions.generation() },
            )?;
            self.sessions.activity_started();
            return Ok(true);
        }
        Ok(false)
    }
    fn mcp_key(&mut self, app: &mut App, key: crossterm::event::KeyEvent) -> Result<bool> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('d') {
            return Ok(true);
        }
        let reject = key.code == KeyCode::Esc || (ctrl && key.code == KeyCode::Char('c'));
        if reject || (key.code == KeyCode::Enter && key.modifiers.is_empty()) {
            if self
                .pending
                .as_ref()
                .is_some_and(|request| matches!(&request.kind, Kind::McpResponse { .. }))
                || self
                    .queued
                    .iter()
                    .any(|(_, kind)| matches!(kind, Kind::McpResponse { .. }))
            {
                bail!("input response is awaiting callback handoff");
            }
            let (request_id, answer) = app
                .mcp_form
                .remote_answer(reject)
                .map_err(anyhow::Error::msg)?;
            let command = iteron_protocol::client_mcp_input::McpInputCommandV1 {
                thread_id: self.service.scope.thread_id.clone(),
                run_id: self.service.current_run_id.clone(),
                command: iteron_protocol::client_mcp_input::McpInputActionV1::Respond {
                    request_id,
                    answer,
                },
            };
            command.validate().map_err(anyhow::Error::msg)?;
            self.queue(
                json!({"type":"mcp_inputs_v1","command":command}),
                Kind::McpResponse {
                    request_id,
                    run: self.service.current_run_id.clone(),
                },
            )?;
            app.status = "input response queued · callback handoff not yet observed".into();
            if ctrl && key.code == KeyCode::Char('c') && self.active_turn().is_some() {
                self.interrupt()?;
            }
        } else {
            super::mcp_input::edit_key(app, key.code, key.modifiers);
        }
        Ok(false)
    }
    fn active_turn(&self) -> Option<iteron_protocol::product_contract::ProductTurnId> {
        self.snapshot
            .as_ref()?
            .turn
            .as_ref()
            .filter(|v| v.state == TurnStateV1::Running)
            .map(|v| v.turn_id)
    }
    fn interrupt(&mut self) -> Result<()> {
        let turn = self
            .active_turn()
            .context("no observed active turn to interrupt")?;
        self.product(json!({"type":"turn_interrupt","thread_id":self.service.scope.thread_id,"turn_id":turn}),Kind::Control)
    }
    fn submit(&mut self, app: &mut App) -> Result<bool> {
        let text = app.editor.text();
        let text = text.trim();
        if text.is_empty() {
            return Ok(false);
        }
        if text.len() > MAX_DRAFT_BYTES {
            bail!("draft exceeds the remote composer's 64 KiB bound");
        }
        if matches!(text, "/quit" | "/detach" | "/exit") {
            return Ok(true);
        }
        if text == "/stop-service" {
            self.queue(json!({"type":"resident_service_v1","command":{"action":"stop","scope":self.service.scope}}),Kind::Stop)?;
            app.editor.clear();
            return Ok(false);
        }
        if text == "/help" {
            app.note(block::NoticeLevel::Info,"Attached service · /detach leaves work running · Esc interrupts the observed turn · /stop-service stops the service. /activity [attach|stop TYPE ID] /agents [COMMAND] /status /permissions /config /models [offset] /model provider:model /artifacts [SHA prefix] /extensions /side question /inputs /input request-id JSON /evidence /refusals /sessions [cursor] /new /resume run-id");
            app.editor.clear();
            return Ok(false);
        }
        if text.starts_with('/') {
            let (verb, arg) = text.split_once(' ').unwrap_or((text, ""));
            let scope = self.scope();
            let control = match verb {
                "/activity" => {
                    let command = super::activity_center::parse(
                        arg,
                        self.service.scope.thread_id.clone(),
                        self.service.current_run_id.clone(),
                    )
                    .map_err(anyhow::Error::msg)?;
                    json!({"type":"activity_center_v1","command":command})
                }
                "/agents" => {
                    let command = super::persistent_agents::parse(
                        app,
                        if arg.is_empty() { "list" } else { arg },
                    )
                    .map_err(anyhow::Error::msg)?;
                    command.validate().map_err(anyhow::Error::msg)?;
                    json!({"type":"agents_v1","command":command})
                }
                "/status" | "/diagnostics" => json!({"type":"operator_status"}),
                "/permissions" if arg.is_empty() => {
                    json!({"type":"inventory_v1","query":{"kind":"permissions"}})
                }
                "/config" if arg.is_empty() => {
                    json!({"type":"inventory_v1","query":{"kind":"effective_config"}})
                }
                "/refusals" => {
                    self.queue(json!({"type":"refusals_v1","command":{"thread_id":self.service.scope.thread_id,"run_id":self.service.current_run_id}}),Kind::Refusals{run:self.service.current_run_id.clone()})?;
                    app.editor.clear();
                    return Ok(false);
                }
                "/evidence" => {
                    self.final_request()?;
                    app.editor.clear();
                    return Ok(false);
                }
                "/sessions" => {
                    if arg.len() > 1024 || arg.chars().any(char::is_control) {
                        bail!("session cursor exceeds its host bound");
                    }
                    let generation = self
                        .sessions
                        .begin(app, self.service.current_run_id.clone());
                    self.sessions_request(
                        (!arg.is_empty()).then(|| arg.to_owned()),
                        generation,
                        false,
                    )?;
                    app.editor.clear();
                    return Ok(false);
                }

                "/artifacts" => {
                    self.queue(json!({"type":"artifacts_v1","command":{"type":"list","thread_id":scope["thread_id"]}}), Kind::ArtifactList { prefix: arg.to_owned(), run: self.service.current_run_id.clone() })?;
                    app.editor.clear();
                    return Ok(false);
                }
                "/extensions" => {
                    json!({"type":"ordinary_extensions_v1","command":{"action":"read","thread_id":scope["thread_id"],"run_id":scope["run_id"],"offset":0,"limit":16}})
                }
                "/inputs" => {
                    self.inputs_request()?;
                    app.editor.clear();
                    return Ok(false);
                }
                "/input" => {
                    let (id, body) = arg
                        .split_once(' ')
                        .context("use /input request-id [field values] or reject")?;
                    let id = id
                        .parse::<u64>()
                        .context("invalid input request identity")?;
                    let answer = if body == "reject" {
                        json!({"action":"reject"})
                    } else {
                        let values: Vec<iteron_protocol::client_mcp_input::McpInputValueV1> =
                            serde_json::from_str(body).map_err(|_| {
                                anyhow::anyhow!(
                                    "input values must be a JSON array of field_index/content"
                                )
                            })?;
                        json!({"action":"approve","values":values})
                    };
                    // No response value is added to the transcript, prompt history or observations.
                    json!({"type":"mcp_inputs_v1","command":{"thread_id":scope["thread_id"],"run_id":scope["run_id"],"command":{"action":"respond","request_id":id,"answer":answer}}})
                }
                "/side" => {
                    use iteron_protocol::client_interaction::{SideActionV1, SideCommandV1};
                    let command = SideCommandV1 {
                        thread_id: self.service.scope.thread_id.clone(),
                        run_id: self.service.current_run_id.clone(),
                        command: match super::control_submission::side_request_for(arg) {
                            crate::app_server::SideRequest::Status => SideActionV1::Status {},
                            crate::app_server::SideRequest::Close => SideActionV1::Close {},
                            crate::app_server::SideRequest::Ask(text) => SideActionV1::Ask { text },
                        },
                    };
                    command.validate().map_err(anyhow::Error::msg)?;
                    json!({"type":"side_v1","command":command})
                }
                "/new" => {
                    json!({"type":"session_navigate_v1","command":{"action":"new","thread_id":scope["thread_id"],"run_id":scope["run_id"]}})
                }
                "/resume" => {
                    json!({"type":"session_navigate_v1","command":{"action":"resume","thread_id":scope["thread_id"],"run_id":scope["run_id"],"target_run_id":arg}})
                }
                "/models" => {
                    let offset = if arg.is_empty() {
                        0
                    } else {
                        arg.parse::<u32>().context("invalid model page")?
                    };
                    self.queue(json!({"type":"inventory_v1","query":{"kind":"models","offset":offset,"limit":100}}),Kind::Models)?;
                    app.editor.clear();
                    return Ok(false);
                }
                "/model" => {
                    let (provider, model) = arg
                        .split_once(':')
                        .context("use /model provider:model after /models")?;
                    let inventory = self
                        .models
                        .as_ref()
                        .context("read /models before selecting a route")?;
                    let row = inventory["records"]
                        .as_array()
                        .context("model inventory unavailable")?
                        .iter()
                        .find(|row| {
                            row["provider_id"] == provider
                                && row["model_id"] == model
                                && row["selectable"] == true
                        })
                        .context("route is not selectable in the captured model page")?;
                    let selection = iteron_protocol::client_inventory::ClientModelSelectionV1 {
                        inventory_digest_sha256: inventory["inventory_digest_sha256"]
                            .as_str()
                            .unwrap_or_default()
                            .into(),
                        provider_id: provider.into(),
                        model_id: model.into(),
                        catalog_digest_sha256: row["catalog_digest_sha256"]
                            .as_str()
                            .unwrap_or_default()
                            .into(),
                        capability_digest_sha256: row["capability_digest_sha256"]
                            .as_str()
                            .unwrap_or_default()
                            .into(),
                    };
                    selection.validate().map_err(anyhow::Error::msg)?;
                    json!({"type":"select_model_v1","selection":selection})
                }
                _ => bail!("unknown attached-client command; use /help"),
            };
            let kind = if matches!(
                verb,
                "/activity"
                    | "/agents"
                    | "/side"
                    | "/status"
                    | "/diagnostics"
                    | "/permissions"
                    | "/config"
            ) {
                Kind::ScopedControl {
                    run: self.service.current_run_id.clone(),
                }
            } else {
                Kind::Control
            };
            self.queue(control, kind)?;
            app.editor.clear();
            return Ok(false);
        }
        if self.accepted.is_some()
            || self
                .pending
                .as_ref()
                .is_some_and(|request| matches!(&request.kind, Kind::Submit { .. }))
            || self
                .queued
                .iter()
                .any(|(_, kind)| matches!(kind, Kind::Submit { .. }))
        {
            bail!("the prior submission is awaiting its host receipt; draft retained");
        }
        let command = if let Some(turn) = self.active_turn() {
            json!({"type":"turn_steer","thread_id":self.service.scope.thread_id,"turn_id":turn,"text":text})
        } else {
            json!({"type":"turn_start","thread_id":self.service.scope.thread_id,"text":text})
        };
        self.product(
            command,
            Kind::Submit {
                draft: text.to_owned(),
                revision: app.editor.persistence_revision(),
            },
        )?;
        Ok(false)
    }
    fn approval_key(&mut self, app: &mut App, code: KeyCode) -> Result<()> {
        if app.permission_prompt.awaiting_response()
            || self
                .pending
                .as_ref()
                .is_some_and(|request| matches!(&request.kind, Kind::Approval { .. }))
            || self
                .queued
                .iter()
                .any(|(_, kind)| matches!(kind, Kind::Approval { .. }))
        {
            return Ok(());
        }
        if let super::permission_prompt::ApprovalInput::Answer { approved, remember } =
            app.permission_prompt.key(code)
        {
            let prompt = app
                .permission_prompt
                .read()
                .context("approval prompt unavailable")?
                .id;
            let turn = self
                .active_turn()
                .context("approval no longer has an observed active turn")?;
            self.product(json!({"type":"approval_respond","thread_id":self.service.scope.thread_id,"turn_id":turn,"approval_id":prompt,"approved":approved,"remember":remember}), Kind::Approval { prompt })?;
        }
        Ok(())
    }
    fn observe_submission(
        &mut self,
        app: &mut App,
        id: SubmissionId,
        state: SubmissionLifecycleState,
    ) {
        let observation = app.run.observe_receipt(id, state);
        if matches!(
            observation,
            super::run_presentation::ReceiptObservation::Refused
        ) && self.expected_submission == Some(id)
        {
            self.expected_submission = None;
        }
        if self.accepted.as_ref().is_none_or(|draft| draft.id != id) {
            return;
        }
        if !matches!(
            state,
            SubmissionLifecycleState::Applied
                | SubmissionLifecycleState::Rejected
                | SubmissionLifecycleState::Expired
        ) {
            return;
        }
        let draft = self.accepted.take().expect("same id checked above");
        if state == SubmissionLifecycleState::Applied {
            app.push_user(draft.draft);
            if app.editor.persistence_revision() == draft.revision {
                let _ = app.editor.take_submit();
            }
        } else {
            app.panel(
                "◇",
                "submission not applied · retained text",
                vec![block::PanelRow::Note(ui_safe_text(&draft.draft))],
            );
        }
    }
    fn reply(&mut self, app: &mut App, id: u64, reply: Value) -> Result<()> {
        let Some(pending) = self.pending.take() else {
            bail!("unsolicited remote control reply");
        };
        if pending.id != id {
            bail!("remote control reply identity changed");
        }
        match pending.kind {
            Kind::Snapshot => {
                let snapshot: ThreadSnapshotV1 = serde_json::from_value(reply["thread"].clone())
                    .context("thread observation unavailable")?;
                if snapshot.contract_version != 1
                    || snapshot.thread_id != self.service.scope.thread_id
                {
                    bail!("thread observation changed service scope");
                }
                if snapshot.run_id != self.service.current_run_id {
                    self.service.current_run_id = snapshot.run_id.clone();
                    self.models = None;
                    self.queued.clear();
                    self.accepted = None;
                    self.expected_submission = None;
                    self.artifact = None;
                    self.last_terminal = None;
                    self.final_needed = false;
                    app.clear_mcp_inputs();
                    self.sessions.clear(app);
                    app.artifact_viewer.close();
                    app.telemetry.observe_remote_cost(None);
                    app.history.clear();
                    app.history.bind_selected_run(&snapshot.run_id);
                    app.run.select_verified_run();
                }
                self.product.select_run(app, snapshot.run_id.clone());
                app.product.observe_snapshot(&snapshot);
                for receipt in &snapshot.submissions {
                    self.observe_submission(app, receipt.submission_id, receipt.state);
                }
                if let Some(turn) = &snapshot.turn
                    && turn.state == TurnStateV1::Running
                    && !app.run.running()
                {
                    if let Some(id) = turn.submission_id {
                        app.run.submission_accepted(id, Instant::now());
                    }
                }
                app.session_name = format!(
                    "Attached · {} · {}",
                    &self.service.scope.service_id[..8],
                    ui_safe_text(&snapshot.run_id.0)
                );
                self.snapshot = Some(snapshot);
                self.poll_events = true;
            }
            Kind::Events => {
                let page: ProductEventsPageV1 = serde_json::from_value(reply["page"].clone())
                    .context("product content observation unavailable")?;
                if page.thread_id != self.service.scope.thread_id || page.events.len() > 64 {
                    bail!("product page scope or bound changed");
                }
                let terminal = page.latest_terminal.clone();
                let source = page
                    .events
                    .iter()
                    .filter_map(|event| event.source_event_seq)
                    .max()
                    .unwrap_or(0);
                for event in &page.events {
                    if event.run_id == self.service.current_run_id
                        && let iteron_protocol::product_contract::ProductEventKindV1::Submission {
                            receipt,
                        } = &event.event
                    {
                        self.observe_submission(app, receipt.submission_id, receipt.state);
                    }
                }
                self.product.ingest_page(app, page, source);
                self.product_cursor = self.product.cursor();
                if let Some(terminal) = terminal {
                    let matches = self
                        .snapshot
                        .as_ref()
                        .and_then(|snapshot| snapshot.turn.as_ref())
                        .is_some_and(|turn| {
                            turn.turn_id == terminal.turn_id
                                && self
                                    .expected_submission
                                    .is_none_or(|expected| turn.submission_id == Some(expected))
                        });
                    if terminal.thread_id == self.service.scope.thread_id
                        && terminal.run_id == self.service.current_run_id
                        && terminal.event_seq > 0
                        && matches
                    {
                        let identity = (
                            terminal.run_id.clone(),
                            terminal.turn_id,
                            terminal.event_seq,
                        );
                        if self.last_terminal.as_ref() != Some(&identity) {
                            self.last_terminal = Some(identity);
                            self.final_needed = true;
                        }
                        app.finish_text_boundary();
                        if let Some(text) = app.product.take_terminal() {
                            app.reconcile_terminal_assistant(&text);
                        }
                        app.flush_text();
                        app.flush_think();
                        app.permission_prompt.clear();
                        app.settle_unfinished_tools();
                        app.run.run_ended(Instant::now());
                        self.expected_submission = None;
                        app.status = "completed · backend remains available".into();
                    }
                }
                self.poll_events = false;
                self.poll_inputs = true;
            }
            Kind::Submit { draft, revision } => {
                if reply["type"] == "control_queued_v1" {
                    let id = reply["submission_id"]
                        .as_u64()
                        .filter(|v| *v > 0)
                        .context("submission receipt unavailable")?;
                    if self.active_turn().is_none() {
                        self.expected_submission = Some(SubmissionId(id));
                        app.run
                            .submission_accepted(SubmissionId(id), Instant::now());
                    }
                    self.accepted = Some(AcceptedDraft {
                        id: SubmissionId(id),
                        draft,
                        revision,
                    });
                    if let Some(snapshot) = &self.snapshot {
                        let known = snapshot
                            .submissions
                            .iter()
                            .find(|receipt| receipt.submission_id == SubmissionId(id))
                            .map(|receipt| receipt.state);
                        if let Some(state) = known {
                            self.observe_submission(app, SubmissionId(id), state);
                        }
                    }
                    app.status = "submission queued · awaiting application".into();
                } else {
                    show_reply(app, &reply);
                }
            }
            Kind::FinalEvidence { run } => {
                if run == self.service.current_run_id {
                    super::final_evidence::remote(
                        app,
                        &reply,
                        &self.service.scope.thread_id,
                        &self.service.scope.tenant,
                        &run,
                    );
                }
                self.final_needed = false;
            }
            Kind::Sessions {
                run,
                generation,
                append,
            } => {
                if run != self.service.current_run_id
                    || !self.sessions.matches(app, &run, generation)
                {
                    return Ok(());
                }
                match self.sessions.page(app, &reply, append) {
                    Ok(super::remote_sessions::Page::Applied) => {}
                    Ok(super::remote_sessions::Page::Restart) => {
                        app.note(
                            block::NoticeLevel::Info,
                            "session index changed; reading the newest page",
                        );
                        self.sessions_request(None, generation, false)?;
                    }
                    Ok(super::remote_sessions::Page::Repair) => {
                        self.queue(
                            json!({"type":"thread_lifecycle_v1","command":{"type":"reindex","thread_id":self.service.scope.thread_id,"run_id":run}}),
                            Kind::SessionsRepair { run, generation },
                        )?;
                    }
                    Err(reason) => {
                        self.sessions.clear(app);
                        app.note(block::NoticeLevel::Warn, reason);
                    }
                }
            }
            Kind::SessionsRepair { run, generation } => {
                if run != self.service.current_run_id
                    || !self.sessions.matches(app, &run, generation)
                {
                    return Ok(());
                }
                if reply["type"] != "thread_reindexed_v1" {
                    self.sessions.clear(app);
                    app.note(
                        block::NoticeLevel::Warn,
                        "service session index repair unconfirmed; reopen to retry",
                    );
                } else {
                    if reply["unavailable"].as_u64().is_some_and(|count| count > 0) {
                        app.note(
                            block::NoticeLevel::Warn,
                            "some retained sessions were unavailable to the host index repair",
                        );
                    }
                    self.sessions_request(None, generation, false)?;
                }
            }
            Kind::SessionsActivity { run, generation } => {
                if run != self.service.current_run_id
                    || !self.sessions.matches(app, &run, generation)
                {
                    return Ok(());
                }
                let Some(snapshot) = self
                    .snapshot
                    .as_ref()
                    .filter(|snapshot| snapshot.run_id == run)
                else {
                    self.sessions.activity_finished();
                    return Ok(());
                };
                self.sessions.activity(app, &reply, snapshot);
                self.queue(
                    json!({"type":"artifacts_v1","command":{"type":"list","thread_id":self.service.scope.thread_id}}),
                    Kind::SessionsChanges { run, generation },
                )?;
            }
            Kind::SessionsChanges { run, generation } => {
                if run != self.service.current_run_id
                    || !self.sessions.matches(app, &run, generation)
                {
                    return Ok(());
                }
                if let Some(snapshot) = self
                    .snapshot
                    .as_ref()
                    .filter(|snapshot| snapshot.run_id == run)
                {
                    self.sessions.changes(app, &reply, snapshot);
                } else {
                    self.sessions.activity_finished();
                }
            }
            Kind::Refusals { run } => {
                if run == self.service.current_run_id {
                    super::refusal::remote(
                        app,
                        &reply,
                        &self.service.scope.thread_id,
                        &self.service.scope.tenant,
                        &run,
                    );
                }
            }
            Kind::Inputs => {
                if reply["type"] == "mcp_inputs_snapshot_v1" {
                    let snapshot: iteron_protocol::client_mcp_input::McpInputsSnapshotV1 =
                        serde_json::from_value(reply["snapshot"].clone())
                            .map_err(|_| anyhow::anyhow!("input observation shape invalid"))?;
                    let was_waiting = app.mcp_form.is_waiting();
                    if let Err(reason) = app.mcp_form.observe_remote(
                        &snapshot,
                        &self.service.scope.thread_id,
                        &self.service.current_run_id,
                    ) {
                        app.note(block::NoticeLevel::Warn, reason);
                    } else if !was_waiting && app.mcp_form.is_waiting() {
                        app.status = "MCP server is waiting for your input".into();
                        self.sessions.clear(app);
                        app.artifact_viewer.close();
                    } else if was_waiting && !app.mcp_form.is_waiting() {
                        app.status = "input callback closed · tool completion not inferred".into();
                    }
                }
                self.poll_inputs = false;
            }
            Kind::McpResponse { request_id, run } => {
                if run != self.service.current_run_id {
                    return Ok(());
                }
                if reply["type"] == "mcp_input_response_v1"
                    && reply["thread_id"] == self.service.scope.thread_id.0
                    && reply["run_id"] == run.0
                    && reply["request_id"].as_u64() == Some(request_id)
                    && matches!(reply["state"].as_str(), Some("answered" | "rejected"))
                {
                    app.mcp_form.remote_handoff(request_id);
                    app.status =
                        "input callback handoff observed · tool completion not inferred".into();
                } else {
                    app.note(
                        block::NoticeLevel::Warn,
                        "input callback handoff was refused or unconfirmed; retained form",
                    );
                }
            }
            Kind::ArtifactList { prefix, run } => {
                if run != self.service.current_run_id {
                    return Ok(());
                }
                if prefix.is_empty() {
                    super::artifacts::render_listing(app, &reply);
                } else {
                    app.artifact_viewer.begin_remote();
                    match super::artifact_view::Transfer::select(
                        self.service.scope.thread_id.clone(),
                        &prefix,
                        &reply,
                    ) {
                        Ok(transfer) => {
                            if self
                                .queue(
                                    json!({"type":"artifacts_v1","command":transfer.command()}),
                                    Kind::ArtifactChunk {
                                        generation: app.artifact_viewer.generation(),
                                    },
                                )
                                .is_ok()
                            {
                                self.artifact = Some((run, transfer));
                            } else {
                                app.artifact_viewer.unavailable("artifact read queue is busy; retry after pending commands finish");
                            }
                        }
                        Err(reason) => app.artifact_viewer.unavailable(reason),
                    }
                }
            }
            Kind::ArtifactChunk { generation } => {
                if !app.artifact_viewer.is_open() || app.artifact_viewer.generation() != generation
                {
                    self.artifact = None;
                    return Ok(());
                }
                let Some((run, mut transfer)) = self.artifact.take() else {
                    app.artifact_viewer
                        .unavailable("artifact transfer unavailable");
                    return Ok(());
                };
                if run != self.service.current_run_id {
                    app.artifact_viewer.close();
                    return Ok(());
                }
                match transfer.accept(&reply) {
                    Ok(true) => {
                        if let Err(reason) = app.artifact_viewer.finish_remote(transfer, run) {
                            app.artifact_viewer.unavailable(reason);
                        }
                    }
                    Ok(false) => {
                        if self
                            .queue(
                                json!({"type":"artifacts_v1","command":transfer.command()}),
                                Kind::ArtifactChunk { generation },
                            )
                            .is_ok()
                        {
                            self.artifact = Some((run, transfer));
                        } else {
                            app.artifact_viewer.unavailable(
                                "artifact read queue is busy; retry after pending commands finish",
                            );
                        }
                    }
                    Err(reason) => app.artifact_viewer.unavailable(reason),
                }
            }
            Kind::Approval { prompt } => {
                if reply["type"] == "control_queued_v1" {
                    let id = reply["submission_id"]
                        .as_u64()
                        .filter(|id| *id > 0)
                        .context("approval response receipt unavailable")?;
                    app.permission_prompt
                        .response_queued(prompt, SubmissionId(id));
                    app.status = "approval response queued · awaiting application".into();
                } else {
                    show_reply(app, &reply);
                }
            }
            Kind::Models => {
                show_reply(app, &reply);
                self.models = Some(reply);
            }
            Kind::Stop => {
                show_reply(app, &reply);
                if reply["type"] == "resident_service_stop_v1" {
                    app.status = "service stop requested · cleanup not yet observed".into();
                }
            }
            Kind::ScopedControl { run } => {
                if run == self.service.current_run_id {
                    show_reply(app, &reply);
                }
            }
            Kind::Control => {
                if reply["type"] == "session_navigated_v1" {
                    let navigation: iteron_protocol::session_navigation::SessionNavigationReplyV1 =
                        serde_json::from_value(reply["navigation"].clone())
                            .context("session navigation observation unavailable")?;
                    if navigation.version != 1
                        || navigation.thread_id != self.service.scope.thread_id
                        || navigation.origin_run_id != self.service.current_run_id
                    {
                        bail!("session navigation scope changed");
                    }
                    self.service.current_run_id = navigation.run_id.clone();
                    self.models = None;
                    self.accepted = None;
                    self.expected_submission = None;
                    self.artifact = None;
                    self.last_terminal = None;
                    self.final_needed = false;
                    app.clear_mcp_inputs();
                    self.sessions.clear(app);
                    app.artifact_viewer.close();
                    app.history.bind_selected_run(&navigation.run_id);
                    app.run.select_verified_run();
                    super::session_adoption::project_host_transcript(app, &navigation.transcript);
                    self.product.select_run(app, navigation.run_id);
                } else {
                    show_reply(app, &reply);
                }
            }
        }
        Ok(())
    }
}
/// Historical machine events have a presentation cursor but no physical run identity. They are
/// not projected by a reattach client. Its Product pages carry the actual thread/run/item scope.
fn ignore_unscoped_event(_event: &Value) {}
fn show_reply(app: &mut App, reply: &Value) {
    if let Ok(refusal) =
        serde_json::from_value::<iteron_protocol::refusal::HostRefusalV1>(reply["refusal"].clone())
    {
        super::refusal::show(app, &refusal);
        return;
    }
    if reply["type"] == "activity_center_v1" {
        super::activity_center::render(app, reply);
        return;
    }
    if matches!(
        reply["type"].as_str(),
        Some("agents_v1" | "agent_observation_v1" | "agent_v1")
    ) {
        super::persistent_agents::render(app, reply);
        return;
    }
    let text = serde_json::to_string(reply).unwrap_or_else(|_| "observation unavailable".into());
    let mut end = text.len().min(16 * 1024);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    app.panel(
        "◇",
        "service reply",
        vec![block::PanelRow::Note(ui_safe_text(&text[..end]))],
    );
    if end < text.len() {
        app.note(
            block::NoticeLevel::Warn,
            "reply display clipped; the host read port remains available",
        );
    }
}

pub(crate) async fn run(endpoint: SocketAddr, expected_service_id: String) -> Result<()> {
    use std::io::IsTerminal as _;
    if !std::io::stdout().is_terminal() {
        bail!("attach requires an interactive terminal");
    }
    if expected_service_id.len() != 64
        || !expected_service_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("attach requires the service identity printed by the listener");
    }
    let mut transport = Transport::connect(endpoint).await?;
    let id = transport
        .control(json!({"type":"resident_service_v1","command":{"action":"read"}}))
        .await?;
    let service = tokio::time::timeout(REPLY_DEADLINE, async {
        for _ in 0..4096 {
            let frame = transport
                .next()
                .await?
                .context("service closed during attachment")?;
            if frame["type"] == "control_reply" && frame["request_id"] == id {
                return serde_json::from_value::<ResidentServiceViewV1>(
                    frame["reply"]["service"].clone(),
                )
                .context("resident service observation unavailable");
            }
            if frame["type"] == "error" {
                bail!("service refused attachment");
            }
        }
        bail!("service attachment exceeded the finite frame budget")
    })
    .await
    .context("resident service observation timed out")??;
    service.scope.validate().map_err(anyhow::Error::msg)?;
    if service.version != RESIDENT_SERVICE_VERSION
        || service.scope.service_id != expected_service_id
        || service.scope.thread_id != transport.thread
        || service.endpoint != endpoint
        || service.stopping
        || service.shutdown_completed
    {
        bail!("listener identity, endpoint or lifecycle does not match the selected service");
    }
    let environment = theme::capabilities::Environment::capture();
    let detected = theme::Theme::detect_with(environment, None);
    let mut app = App::new_with_detected_theme(detected);
    app.telemetry.observe_remote_cost(None);
    app.status = "attached · /detach leaves backend work running".into();
    app.keymap_status = "attached client".into();
    app.history.bind_selected_run(&service.current_run_id);
    let guard = TermGuard::new()?;
    let (termination_tx, mut termination_rx) = mpsc::channel::<()>(1);
    #[cfg(unix)]
    let mut signal_tasks = Vec::new();
    #[cfg(not(unix))]
    let signal_tasks = Vec::new();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        for kind in [SignalKind::terminate(), SignalKind::hangup()] {
            let mut signal = signal(kind).context("attach termination signal unavailable")?;
            let keyboard = guard.keyboard_restorer();
            let sender = termination_tx.clone();
            signal_tasks.push(tokio::spawn(async move {
                signal.recv().await;
                super::terminal_lifecycle::restore_terminal(&keyboard);
                let _ = sender.send(()).await;
            }));
        }
    }
    struct SignalTasks(Vec<tokio::task::JoinHandle<()>>);
    impl Drop for SignalTasks {
        fn drop(&mut self) {
            for task in &self.0 {
                task.abort();
            }
        }
    }
    let _signals = SignalTasks(signal_tasks);
    let _termination_tx = termination_tx;
    let (writer, _notifications) = notification::LiveTerminalWriter::stdout();
    let mut terminal = Terminal::new(CrosstermBackend::new(writer))?;
    let mut input = Input::start();
    let mut view = View {
        service,
        snapshot: None,
        product: ProductProjection::remote(),
        pending: None,
        queued: std::collections::VecDeque::new(),
        models: None,
        sessions: Default::default(),
        product_cursor: 0,
        poll_events: false,
        poll_inputs: false,
        last_terminal: None,
        final_needed: false,
        last_live_seq: 0,
        accepted: None,
        expected_submission: None,
        artifact: None,
    };
    view.snapshot_request()?;
    let mut tick = tokio::time::interval(POLL_PERIOD);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if view.pending.is_none()
            && let Some((control, kind)) = view.queued.pop_front()
        {
            let id = transport.control(control).await?;
            view.pending = Some(Request {
                id,
                kind,
                deadline: Instant::now() + REPLY_DEADLINE,
            });
        }
        app.artifact_viewer.poll(&view.service.current_run_id);
        if app.permission_prompt.read().is_some() || app.mcp_form.is_waiting() {
            view.sessions.clear(&mut app);
        }
        terminal.draw(|frame| draw(frame, &mut app))?;
        tokio::select! {
            _=termination_rx.recv()=>break,
            frame=transport.next()=>{
                let Some(frame)=frame?else{app.status="service connection closed; completion was not inferred".into();break;};
                match frame["type"].as_str() {
                    Some("control_reply")=>view.reply(&mut app,frame["request_id"].as_u64().context("reply identity unavailable")?,frame["reply"].clone())?,
                    Some("event")|Some("result")=>{
                        let seq=frame["seq"].as_u64().filter(|v|*v>view.last_live_seq).context("service presentation sequence did not advance")?;view.last_live_seq=seq;
                        // Frozen machine frames lack Product turn scope. Neither an old result
                        // nor an old tool event can mutate this selected run or release input.
                        if frame["type"]=="event" {ignore_unscoped_event(&frame["event"]);}
                    },
                    Some("error")=>{show_reply(&mut app,&frame);},
                    _=>{},
                }
            },
            incoming=input.receiver.recv()=>{
                let Some(incoming)=incoming else{break;};
                let ReadResult::Event(event)=incoming?else{continue;};
                match event {
                    Event::Key(key) if key.kind!=KeyEventKind::Release=>{
                        if app.permission_prompt.read().is_some() || app.mcp_form.is_waiting() { app.artifact_viewer.close(); }
                        if app.artifact_viewer.is_open() && !key.modifiers.contains(KeyModifiers::CONTROL) {app.artifact_viewer.key(key.code);continue;}
                        if key.modifiers.contains(KeyModifiers::CONTROL) { app.artifact_viewer.close(); }
                        if app.mcp_form.is_waiting() {
                            match view.mcp_key(&mut app,key) {Ok(true)=>break,Ok(false)=>{},Err(error)=>app.note(block::NoticeLevel::Warn,error.to_string())};
                            continue;
                        }
                        if app.pickers.has_remote_sessions() && app.permission_prompt.read().is_none() {
                            match view.sessions_key(&mut app,key) {Ok(true)=>break,Ok(false)=>{},Err(error)=>app.note(block::NoticeLevel::Warn,error.to_string())};
                            continue;
                        }
                        if app.permission_prompt.read().is_some() {
                            view.sessions.clear(&mut app);
                            if let Err(error) = view.approval_key(&mut app, key.code) { app.note(block::NoticeLevel::Warn, error.to_string()); }
                            continue;
                        }
                        if key.modifiers.contains(KeyModifiers::CONTROL)&&matches!(key.code,KeyCode::Char('d')){break;}
                        if key.modifiers.contains(KeyModifiers::CONTROL)&&matches!(key.code,KeyCode::Char('c')) {
                            if view.active_turn().is_some(){if let Err(error)=view.interrupt(){app.note(block::NoticeLevel::Warn,error.to_string());}}else{break;}
                        } else {match key.code {
                            KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL)=>app.editor.newline(),
                            KeyCode::Enter=>match view.submit(&mut app){Ok(true)=>break,Ok(false)=>{},Err(error)=>app.note(block::NoticeLevel::Warn,error.to_string())},
                            KeyCode::Esc=>if view.active_turn().is_some(){if let Err(error)=view.interrupt(){app.note(block::NoticeLevel::Warn,error.to_string());}}else{break;},
                            KeyCode::Char(c) if !key.modifiers.intersects(KeyModifiers::CONTROL|KeyModifiers::ALT)=>{if app.editor.text().len()<MAX_DRAFT_BYTES{app.editor.insert(c);}},
                            KeyCode::Backspace=>app.editor.backspace(),KeyCode::Delete=>app.editor.delete(),KeyCode::Left=>app.editor.left(),KeyCode::Right=>app.editor.right(),
                            KeyCode::Home=>app.editor.home(),KeyCode::End=>app.editor.end(),KeyCode::Up=>app.editor.history_prev(),KeyCode::Down=>app.editor.history_next(),
                            KeyCode::PageUp=>app.scroll_up(10),KeyCode::PageDown=>app.scroll_down(10),_=>{},
                        }}
                    },
                    Event::Paste(text) if app.mcp_form.is_waiting()=>super::mcp_input::handle_paste(&mut app,&text),
                    Event::Paste(text) if app.pickers.has_remote_sessions()=>{app.pickers.paste(&text);},
                    Event::Paste(text)=>{if app.editor.text().len().saturating_add(text.len())<=MAX_DRAFT_BYTES{app.editor.insert_str(&crate::editor::sanitize_foreign_text(&text));}else{app.note(block::NoticeLevel::Warn,"paste exceeds the bounded remote draft; retained current text");}},
                    _=>{},
                }
            },
            _=tick.tick()=>{
                if view.pending.as_ref().is_some_and(|request|Instant::now()>request.deadline){bail!("remote reply timed out; command delivery/continuation is unconfirmed");}
                if view.pending.is_none()&&view.queued.is_empty(){if view.final_needed{view.final_request()?;}else if view.poll_inputs{view.inputs_request()?;}else if view.sessions_poll(&app)?{}else if view.poll_events{view.events_request()?;}else{view.snapshot_request()?;}}
            },
        }
    }
    // No process handle, runtime Drop, Op::Drain, service stop or provider constructor is here.
    drop(input);
    drop(terminal);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attached_owner_controls_keep_actual_arguments_and_scope_in_the_public_activity_contract() {
        let mut app = App::new();
        let mut view = view();
        for (text, verb, target) in [
            (
                "/activity attach process proc-native-1",
                "inspect",
                "proc-native-1",
            ),
            (
                "/activity stop process proc-native-1",
                "stop",
                "proc-native-1",
            ),
        ] {
            app.editor.clear();
            app.editor.insert_str(text);
            assert!(!view.submit(&mut app).unwrap());
            let (wire, kind) = view.queued.pop_front().unwrap();
            assert!(matches!(kind, Kind::ScopedControl { run } if run.0 == "run"));
            assert_eq!(wire["command"]["action"], verb);
            assert_eq!(wire["command"]["target"]["job_id"], target);
            assert_eq!(wire["command"]["thread_id"], "thread");
            assert_eq!(wire["command"]["run_id"], "run");
            let parsed: iteron_protocol::activity_control::ActivityControlV1 =
                serde_json::from_value(wire["command"].clone()).unwrap();
            assert_eq!(parsed.is_read_only(), verb == "inspect");
        }
        for (text, action) in [("/side status", "status"), ("/side close", "close")] {
            app.editor.clear();
            app.editor.insert_str(text);
            view.submit(&mut app).unwrap();
            let (wire, _) = view.queued.pop_front().unwrap();
            assert_eq!(wire["command"]["command"]["action"], action);
            assert!(wire["command"]["command"]["text"].is_null());
        }
        app.editor.insert_str("/agents interrupt 7");
        assert!(
            view.submit(&mut app).is_err(),
            "no observed epoch cannot dispatch an interrupt"
        );
        assert!(view.queued.is_empty());
        assert_eq!(app.editor.text(), "/agents interrupt 7");
        app.editor.clear();
        app.editor
            .insert_str("/agents followup 7 continue this task");
        view.submit(&mut app).unwrap();
        let (wire, _) = view.queued.pop_front().unwrap();
        let command: iteron_protocol::client_agent_control::ClientAgentControlV1 =
            serde_json::from_value(wire["command"].clone()).unwrap();
        assert!(
            matches!(command,iteron_protocol::client_agent_control::ClientAgentControlV1::Command {
            command:iteron_protocol::agent_control::AgentCommandV1::FollowupTask { agent_id, .. }, ..
        } if agent_id.0 == 7)
        );
    }
    #[test]
    fn closed_or_foreign_run_control_reply_never_relabels_a_new_selected_run() {
        let mut app = App::new();
        let mut view = view();
        view.pending = Some(Request {
            id: 1,
            kind: Kind::ScopedControl {
                run: iteron_protocol::RunId("old".into()),
            },
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.reply(
            &mut app,
            1,
            json!({"type":"activity_center_v1","data":{"activities":[]}}),
        )
        .unwrap();
        assert!(app.history.blocks().is_empty());
        assert!(view.queued.is_empty());
        app.editor.insert_str("/status");
        view.submit(&mut app).unwrap();
        let (wire, kind) = view.queued.pop_front().unwrap();
        assert_eq!(wire["type"], "operator_status");
        assert!(matches!(kind, Kind::ScopedControl { run } if run.0 == "run"));
    }
    fn view() -> View {
        View {
            service: ResidentServiceViewV1 {
                version: 1,
                scope: iteron_protocol::resident_service::ResidentServiceScopeV1 {
                    service_id: "a".repeat(64),
                    thread_id: iteron_protocol::SessionId("thread".into()),
                    tenant: iteron_protocol::TenantId::default(),
                    workspace_sha256: "b".repeat(64),
                },
                endpoint: "127.0.0.1:12345".parse().unwrap(),
                current_run_id: iteron_protocol::RunId("run".into()),
                stopping: false,
                shutdown_completed: false,
            },
            snapshot: None,
            product: ProductProjection::remote(),
            pending: None,
            queued: Default::default(),
            models: None,
            sessions: Default::default(),
            product_cursor: 0,
            poll_events: false,
            poll_inputs: false,
            last_terminal: None,
            final_needed: false,
            last_live_seq: 0,
            accepted: None,
            expected_submission: None,
            artifact: None,
        }
    }
    #[test]
    fn queued_reply_does_not_claim_application_and_exact_receipt_preserves_new_draft() {
        let mut app = App::new();
        let mut view = view();
        app.editor.insert_str("the original task");
        let revision = app.editor.persistence_revision();
        view.pending = Some(Request {
            id: 1,
            kind: Kind::Submit {
                draft: "the original task".into(),
                revision,
            },
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.reply(
            &mut app,
            1,
            json!({"type":"control_queued_v1","submission_id":7}),
        )
        .unwrap();
        assert_eq!(app.editor.text(), "the original task");
        assert!(
            app.run.running(),
            "the actual SQ receipt reserves input until real host termination"
        );
        view.observe_submission(&mut app, SubmissionId(8), SubmissionLifecycleState::Applied);
        assert!(view.accepted.is_some());
        app.editor.clear();
        app.editor.insert_str("new draft");
        view.observe_submission(&mut app, SubmissionId(7), SubmissionLifecycleState::Applied);
        assert!(view.accepted.is_none());
        assert_eq!(app.editor.text(), "new draft");
        assert!(app.history.blocks().iter().any(
            |block| matches!(&block.kind,block::BlockKind::User(text) if text=="the original task")
        ));
    }
    #[test]
    fn refused_submission_keeps_owned_text_and_never_dispatches_drain_on_detach() {
        let mut app = App::new();
        let mut view = view();
        app.editor.insert_str("retained task");
        view.accepted = Some(AcceptedDraft {
            id: SubmissionId(5),
            draft: "retained task".into(),
            revision: app.editor.persistence_revision(),
        });
        view.observe_submission(
            &mut app,
            SubmissionId(5),
            SubmissionLifecycleState::Rejected,
        );
        assert_eq!(app.editor.text(), "retained task");
        assert!(!app.run.running());
        app.editor.clear();
        app.editor.insert_str("/detach");
        assert!(view.submit(&mut app).unwrap());
        assert!(view.queued.is_empty());
    }
    #[test]
    fn actual_rejection_releases_only_unadmitted_submission_and_accepts_the_next_identity() {
        let mut app = App::new();
        let mut view = view();
        app.editor.insert_str("first");
        view.pending = Some(Request {
            id: 1,
            kind: Kind::Submit {
                draft: "first".into(),
                revision: app.editor.persistence_revision(),
            },
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.reply(
            &mut app,
            1,
            json!({"type":"control_queued_v1","submission_id":4}),
        )
        .unwrap();
        assert!(app.run.running());
        view.observe_submission(
            &mut app,
            SubmissionId(99),
            SubmissionLifecycleState::Rejected,
        );
        assert!(app.run.running());
        view.observe_submission(
            &mut app,
            SubmissionId(4),
            SubmissionLifecycleState::Rejected,
        );
        assert!(!app.run.running());
        assert!(view.expected_submission.is_none());
        assert_eq!(app.editor.text(), "first");
        app.editor.clear();
        app.editor.insert_str("second");
        view.pending = Some(Request {
            id: 2,
            kind: Kind::Submit {
                draft: "second".into(),
                revision: app.editor.persistence_revision(),
            },
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.reply(
            &mut app,
            2,
            json!({"type":"control_queued_v1","submission_id":5}),
        )
        .unwrap();
        view.observe_submission(
            &mut app,
            SubmissionId(5),
            SubmissionLifecycleState::Admitted,
        );
        view.observe_submission(
            &mut app,
            SubmissionId(5),
            SubmissionLifecycleState::Rejected,
        );
        assert!(
            app.run.running(),
            "a rejected receipt cannot undo actual prior admission"
        );
        assert_eq!(view.expected_submission, Some(SubmissionId(5)));
    }

    #[test]
    fn delayed_old_machine_event_after_navigation_cannot_contaminate_selected_run() {
        let mut app = App::new();
        let mut view = view();
        app.run.submission_accepted(SubmissionId(1), Instant::now());
        view.service.current_run_id = iteron_protocol::RunId("new-run".into());
        app.history.clear();
        app.history.bind_selected_run(&view.service.current_run_id);
        view.product
            .select_run(&mut app, view.service.current_run_id.clone());
        let before = app.history.revision();
        ignore_unscoped_event(
            &json!({"type":"tool_start","tool_use_id":"old-call","name":"write_file","args":{"path":"old-run.txt"}}),
        );
        ignore_unscoped_event(
            &json!({"type":"tool_end","tool_use_id":"old-call","ok":true,"output":"old secret output"}),
        );
        ignore_unscoped_event(&json!({"type":"run_done"}));
        assert_eq!(app.history.revision(), before);
        assert!(app.run.running());
        use iteron_protocol::product_contract::{
            ItemContentChannelV1, ItemKindV1, ItemStateV1, ProductEventKindV1, ProductEventV1,
            ProductEventsPageV1, ProductTurnId,
        };
        let make = |seq, run: &str, event| ProductEventV1 {
            event_seq: seq,
            source_event_seq: Some(seq),
            thread_id: view.service.scope.thread_id.clone(),
            run_id: iteron_protocol::RunId(run.into()),
            turn_id: Some(ProductTurnId(1)),
            item_id: Some("same-item-id".into()),
            event,
        };
        let page = ProductEventsPageV1 {
            contract_version: 1,
            thread_id: view.service.scope.thread_id.clone(),
            requested_after: 0,
            oldest_available: 1,
            latest_cursor: 5,
            next_cursor: 5,
            latest_terminal: None,
            gap: None,
            events: vec![
                make(
                    1,
                    "old-run",
                    ProductEventKindV1::ItemStarted {
                        kind: ItemKindV1::ToolCall,
                        title: Some("write_file".into()),
                    },
                ),
                make(
                    2,
                    "old-run",
                    ProductEventKindV1::ItemContent {
                        channel: ItemContentChannelV1::ToolOutput,
                        content: "old secret output".into(),
                    },
                ),
                make(
                    3,
                    "new-run",
                    ProductEventKindV1::ItemStarted {
                        kind: ItemKindV1::ToolCall,
                        title: Some("read_file".into()),
                    },
                ),
                make(
                    4,
                    "new-run",
                    ProductEventKindV1::ItemContent {
                        channel: ItemContentChannelV1::ToolOutput,
                        content: "same scoped public bytes".into(),
                    },
                ),
                make(
                    5,
                    "new-run",
                    ProductEventKindV1::ItemEnded {
                        state: ItemStateV1::Completed,
                    },
                ),
            ],
        };
        view.product.ingest_page(&mut app, page, 5);
        let text = app
            .history
            .blocks()
            .iter()
            .map(|block| block.to_text())
            .collect::<String>();
        assert!(text.contains("same scoped public bytes"));
        assert!(!text.contains("old secret output"));
        assert!(!text.contains("write_file"));
    }
    #[tokio::test]
    async fn remote_artifact_download_preserves_all_chunks_and_cancelled_scope_is_not_reused() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let bytes = format!("{}REMOTE-ARTIFACT-TAIL", "x".repeat(100_000)).into_bytes();
        let descriptor = iteron_protocol::client_artifact::ClientArtifactDescriptorV1 {
            artifact_id: hex::encode(Sha256::digest(&bytes)),
            schema: "iteron.fixture.v1".into(),
            mime_type: "text/plain".into(),
            bytes: bytes.len() as u64,
            complete: true,
            required_capability: iteron_protocol::Capability::ReadOnly,
            source_event_seq: 23,
        };
        let mut app = App::new();
        let mut view = view();
        view.pending = Some(Request {
            id: 1,
            kind: Kind::ArtifactList {
                prefix: descriptor.artifact_id[..12].into(),
                run: view.service.current_run_id.clone(),
            },
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.reply(
            &mut app,
            1,
            json!({"type":"artifacts_v1","contract_version":1,"artifacts":[descriptor]}),
        )
        .unwrap();
        let mut offset = 0;
        for (index, bytes) in bytes.chunks(64 * 1024).enumerate() {
            let (request, kind) = view.queued.pop_front().unwrap();
            assert_eq!(request["command"]["artifact_id"], descriptor.artifact_id);
            assert_eq!(request["command"]["offset"], offset);
            let end = offset + bytes.len();
            view.pending = Some(Request {
                id: index as u64 + 2,
                kind,
                deadline: Instant::now() + REPLY_DEADLINE,
            });
            view.reply(&mut app,index as u64+2,json!({"type":"artifact_chunk_v1","contract_version":1,"artifact":descriptor,"offset":offset,"next_offset":end,"eof":end==descriptor.bytes as usize,"content_base64":base64::engine::general_purpose::STANDARD.encode(bytes)})).unwrap();
            offset = end;
        }
        assert_eq!(offset, bytes.len());
        assert!(view.artifact.is_none());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !app.artifact_viewer.poll(&view.service.current_run_id) {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for _ in 0..bytes.len().div_ceil(8192) - 1 {
            app.artifact_viewer.key(KeyCode::Right);
        }
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 100)).unwrap();
        terminal
            .draw(|frame| super::super::artifact_view::render(frame, &app.artifact_viewer))
            .unwrap();
        let screen = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(screen.contains("REMOTE-ARTIFACT-TAIL"));
        assert!(screen.contains("SHA-256 verified"));
        let generation = app.artifact_viewer.generation();
        app.artifact_viewer.close();
        view.pending = Some(Request {
            id: 4,
            kind: Kind::ArtifactChunk { generation },
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.reply(
            &mut app,
            4,
            json!({"type":"artifact_chunk_v1","artifact":{"source_event_seq":999}}),
        )
        .unwrap();
        assert!(!app.artifact_viewer.is_open());
        assert!(view.artifact.is_none());
        assert!(view.queued.is_empty());
        view.pending = Some(Request {
            id: 5,
            kind: Kind::ArtifactList {
                prefix: descriptor.artifact_id.clone(),
                run: view.service.current_run_id.clone(),
            },
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.service.current_run_id = iteron_protocol::RunId("new".into());
        view.reply(
            &mut app,
            5,
            json!({"type":"artifacts_v1","contract_version":1,"artifacts":[descriptor]}),
        )
        .unwrap();
        assert!(!app.artifact_viewer.is_open());
        assert!(view.queued.is_empty());
    }
    #[test]
    fn attached_modal_callback_ack_is_scoped_and_detach_never_rejects_the_pending_request() {
        let mut app = App::new();
        let mut view = view();
        let snapshot = json!({"version":1,"thread_id":view.service.scope.thread_id,"run_id":view.service.current_run_id,"revision":1,"pending":[{"request_id":6,"server_display":"alpha","tool_display":"profile","fields":[{"field_index":0,"prompt":"Enter name","schema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}],"prompt_complete":true}],"closed":[],"omitted_closed":0});
        view.pending = Some(Request {
            id: 1,
            kind: Kind::Inputs,
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.reply(
            &mut app,
            1,
            json!({"type":"mcp_inputs_snapshot_v1","snapshot":snapshot}),
        )
        .unwrap();
        assert!(app.mcp_form.is_waiting());
        super::super::mcp_input::handle_paste(&mut app, r#"{"name":"private-response"}"#);
        assert!(
            view.mcp_key(
                &mut app,
                crossterm::event::KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL)
            )
            .unwrap()
        );
        assert!(view.queued.is_empty());
        assert!(app.mcp_form.is_waiting());
        view.mcp_key(
            &mut app,
            crossterm::event::KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .unwrap();
        assert!(app.mcp_form.is_waiting());
        assert!(app.editor.text().is_empty());
        assert!(app.history.blocks().is_empty());
        assert!(
            view.mcp_key(
                &mut app,
                crossterm::event::KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)
            )
            .is_err()
        );
        let (command, kind) = view.queued.pop_front().unwrap();
        assert_eq!(
            command["command"]["command"]["answer"]["values"][0]["content"]["name"],
            "private-response"
        );
        view.pending = Some(Request {
            id: 2,
            kind,
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.reply(&mut app,2,json!({"type":"mcp_input_response_v1","thread_id":view.service.scope.thread_id,"run_id":"foreign","request_id":6,"state":"answered"})).unwrap();
        assert!(app.mcp_form.is_waiting());
        view.pending = Some(Request {
            id: 3,
            kind: Kind::McpResponse {
                request_id: 6,
                run: view.service.current_run_id.clone(),
            },
            deadline: Instant::now() + REPLY_DEADLINE,
        });
        view.reply(&mut app,3,json!({"type":"mcp_input_response_v1","thread_id":view.service.scope.thread_id,"run_id":view.service.current_run_id,"request_id":6,"state":"answered"})).unwrap();
        assert!(!app.mcp_form.is_waiting());
        assert!(!app.run.running());
        assert!(app.status.contains("completion not inferred"));
        assert!(
            app.history
                .blocks()
                .iter()
                .all(|block| !block.to_text().contains("private-response"))
        );
    }
}
