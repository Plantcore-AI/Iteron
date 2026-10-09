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
    Submit { draft: String, revision: u64 },
    Control,
    Approval { prompt: SubmissionId },
    Models,
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
    product_cursor: u64,
    poll_events: bool,
    last_live_seq: u64,
    accepted: Option<AcceptedDraft>,
    expected_submission: Option<SubmissionId>,
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
            app.note(block::NoticeLevel::Info,"Attached service · /detach leaves work running · Esc interrupts the observed turn · /stop-service stops the service. /activity /agents /models [offset] /model provider:model /artifacts /extensions /side question /inputs /input request-id JSON /new /resume run-id");
            app.editor.clear();
            return Ok(false);
        }
        if text.starts_with('/') {
            let (verb, arg) = text.split_once(' ').unwrap_or((text, ""));
            let scope = self.scope();
            let control = match verb {
                "/activity" => {
                    json!({"type":"activity_center_v1","command":{"action":"list","thread_id":scope["thread_id"],"run_id":scope["run_id"]}})
                }
                "/agents" => json!({"type":"agents_v1","command":{"type":"list"}}),
                "/artifacts" => {
                    json!({"type":"artifacts_v1","command":{"type":"list","thread_id":scope["thread_id"]}})
                }
                "/extensions" => {
                    json!({"type":"ordinary_extensions_v1","command":{"action":"read","thread_id":scope["thread_id"],"run_id":scope["run_id"],"offset":0,"limit":16}})
                }
                "/inputs" => {
                    json!({"type":"mcp_inputs_v1","command":{"thread_id":scope["thread_id"],"run_id":scope["run_id"],"command":{"action":"read"}}})
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
                    json!({"type":"side_v1","command":{"thread_id":scope["thread_id"],"run_id":scope["run_id"],"command":{"action":"ask","text":arg}}})
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
            self.queue(control, Kind::Control)?;
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
        product_cursor: 0,
        poll_events: false,
        last_live_seq: 0,
        accepted: None,
        expected_submission: None,
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
                        if app.permission_prompt.read().is_some() {
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
                    Event::Paste(text)=>{if app.editor.text().len().saturating_add(text.len())<=MAX_DRAFT_BYTES{app.editor.insert_str(&crate::editor::sanitize_foreign_text(&text));}else{app.note(block::NoticeLevel::Warn,"paste exceeds the bounded remote draft; retained current text");}},
                    _=>{},
                }
            },
            _=tick.tick()=>{
                if view.pending.as_ref().is_some_and(|request|Instant::now()>request.deadline){bail!("remote reply timed out; command delivery/continuation is unconfirmed");}
                if view.pending.is_none()&&view.queued.is_empty(){if view.poll_events{view.events_request()?;}else{view.snapshot_request()?;}}
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
            product_cursor: 0,
            poll_events: false,
            last_live_seq: 0,
            accepted: None,
            expected_submission: None,
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
}
