//! One bounded input-callback owner shared by local forms and authenticated clients.
use super::{EventPublisher, ServerEvent};
mod request_bounds;
use iteron_mcp::{McpFuture, McpInputDecision, McpInputRequest, McpMrtrHandler};
use iteron_protocol::client_mcp_input::{
    MCP_INPUT_CONTRACT_VERSION, McpInputClosedV1, McpInputFieldViewV1, McpInputPromptViewV1,
    McpInputStateV1, McpInputsSnapshotV1, response_value_bytes,
};
use iteron_protocol::{RunId, SessionId};
pub(crate) use request_bounds::prompt_view_fits;
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, mpsc, oneshot};

pub(crate) const MAX_CAPACITY: usize = 8;
const MAX_CLOSED_INPUTS: usize = 64;
const MAX_PROMPT_BYTES: usize = 128 * 1024;
const MAX_INPUT_WAIT: Duration = Duration::from_secs(120);

pub(crate) fn capacity() -> usize {
    iteron_tunables::param_usize("cli.app_server.mcp_input.max_capacity", MAX_CAPACITY)
        .clamp(1, MAX_CAPACITY)
}
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct McpInputField {
    pub(crate) id: String,
    pub(crate) prompt: String,
    pub(crate) schema: Value,
}
#[derive(Clone, PartialEq)]
pub(crate) struct McpInputPrompt {
    pub(crate) request_id: u64,
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) request_state: Option<String>,
    pub(crate) fields: Vec<McpInputField>,
}
impl std::fmt::Debug for McpInputPrompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpInputPrompt")
            .field("request_id", &self.request_id)
            .field("fields", &self.fields.len())
            .finish_non_exhaustive()
    }
}
pub(crate) enum McpInputAnswer {
    Approve(Vec<(String, Value)>),
    Reject,
}
pub(crate) struct McpInputResponse {
    pub(crate) request_id: u64,
    pub(crate) answer: McpInputAnswer,
}
pub(super) struct McpInputRequestEnvelope {
    prompt: McpInputPrompt,
    reply: oneshot::Sender<McpInputDecision>,
}

struct PendingInput {
    prompt: McpInputPrompt,
    scope: Option<(SessionId, RunId)>,
    reply: oneshot::Sender<McpInputDecision>,
}
struct ClosedInput {
    scope: Option<(SessionId, RunId)>,
    observation: McpInputClosedV1,
}
#[derive(Default)]
struct InputsState {
    pending: BTreeMap<u64, PendingInput>,
    closed: VecDeque<ClosedInput>,
    revision: u64,
    omitted_closed: u64,
}
struct BridgeHandler {
    requests: mpsc::Sender<McpInputRequestEnvelope>,
    next_id: AtomicU64,
    state: Mutex<InputsState>,
    changed: Notify,
}
/// Every handle refers to the existing handler Arc, never a second pending-request table.
#[derive(Clone)]
pub(super) struct PendingInputs(Arc<BridgeHandler>);
impl PendingInputs {
    pub(super) fn handler(&self) -> Arc<dyn McpMrtrHandler> {
        self.0.clone()
    }
    pub(super) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.lock().pending.len()
    }
    pub(super) fn snapshot(&self, thread: &SessionId, run: &RunId) -> McpInputsSnapshotV1 {
        let state = self.0.lock();
        let matches = |scope: &Option<(SessionId, RunId)>| {
            scope.as_ref().is_some_and(|(t, r)| t == thread && r == run)
        };
        McpInputsSnapshotV1 {
            version: MCP_INPUT_CONTRACT_VERSION,
            thread_id: thread.clone(),
            run_id: run.clone(),
            revision: state.revision,
            pending: state
                .pending
                .values()
                .filter(|entry| matches(&entry.scope))
                .map(|entry| prompt_view(&entry.prompt))
                .collect(),
            closed: state
                .closed
                .iter()
                .filter(|entry| matches(&entry.scope))
                .map(|entry| entry.observation.clone())
                .collect(),
            // This is the finite owner's total omitted closed history, not a durable per-run stream.
            omitted_closed: state.omitted_closed,
        }
    }
    pub(super) async fn wait(
        &self,
        thread: &SessionId,
        run: &RunId,
        after: u64,
        timeout_ms: u32,
    ) -> McpInputsSnapshotV1 {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            // Register before the read, so a response between read and await cannot be lost.
            changed.as_mut().enable();
            let view = self.snapshot(thread, run);
            if view.revision > after || tokio::time::Instant::now() >= deadline {
                return view;
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                return self.snapshot(thread, run);
            }
        }
    }
    pub(super) fn field_identities(
        &self,
        thread: &SessionId,
        run: &RunId,
        id: u64,
    ) -> Option<Vec<String>> {
        let state = self.0.lock();
        let entry = state.pending.get(&id)?;
        if entry
            .scope
            .as_ref()
            .is_none_or(|(t, r)| t != thread || r != run)
            || entry.reply.is_closed()
        {
            return None;
        }
        Some(
            entry
                .prompt
                .fields
                .iter()
                .map(|field| field.id.clone())
                .collect(),
        )
    }
    pub(super) fn respond_scoped(
        &self,
        thread: &SessionId,
        run: &RunId,
        response: McpInputResponse,
        require_complete: bool,
    ) -> Result<McpInputStateV1, &'static str> {
        self.0
            .resolve(Some((thread, run)), response, require_complete)
    }
}
#[cfg(test)]
impl Default for PendingInputs {
    fn default() -> Self {
        wire().1.owner
    }
}

impl BridgeHandler {
    fn lock(&self) -> std::sync::MutexGuard<'_, InputsState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn close(&self, id: u64, reason: McpInputStateV1) {
        let mut state = self.lock();
        if let Some(entry) = state.pending.remove(&id) {
            record_closed(&mut state, id, entry.scope, reason);
            self.changed.notify_waiters();
        }
    }
    fn resolve(
        &self,
        scope: Option<(&SessionId, &RunId)>,
        response: McpInputResponse,
        require_complete: bool,
    ) -> Result<McpInputStateV1, &'static str> {
        let mut state = self.lock();
        let entry = state
            .pending
            .get(&response.request_id)
            .ok_or("input request is no longer pending")?;
        if entry.reply.is_closed() {
            return Err("input callback is no longer waiting");
        }
        if let Some((thread, run)) = scope
            && entry
                .scope
                .as_ref()
                .is_none_or(|(t, r)| t != thread || r != run)
        {
            return Err("input request scope mismatch");
        }
        if let McpInputAnswer::Approve(values) = &response.answer {
            if require_complete && !prompt_view(&entry.prompt).prompt_complete {
                return Err("input prompt cannot be represented completely");
            }
            validate_values(&entry.prompt, values)?;
        }
        let entry = state
            .pending
            .remove(&response.request_id)
            .expect("validated under same owner lock");
        let (decision, observed) = match response.answer {
            McpInputAnswer::Approve(values) => {
                (McpInputDecision::Approve(values), McpInputStateV1::Answered)
            }
            McpInputAnswer::Reject => (McpInputDecision::Reject, McpInputStateV1::Rejected),
        };
        let observed = if entry.reply.send(decision).is_ok() {
            observed
        } else {
            McpInputStateV1::Cancelled
        };
        record_closed(&mut state, response.request_id, entry.scope, observed);
        self.changed.notify_waiters();
        if observed == McpInputStateV1::Cancelled {
            Err("input callback is no longer waiting")
        } else {
            Ok(observed)
        }
    }
}
fn record_closed(
    state: &mut InputsState,
    id: u64,
    scope: Option<(SessionId, RunId)>,
    reason: McpInputStateV1,
) {
    state.revision = state.revision.saturating_add(1);
    if state.closed.len() >= MAX_CLOSED_INPUTS {
        state.closed.pop_front();
        state.omitted_closed = state.omitted_closed.saturating_add(1);
    }
    state.closed.push_back(ClosedInput {
        scope,
        observation: McpInputClosedV1 {
            request_id: id,
            revision: state.revision,
            state: reason,
        },
    });
}
fn validate_values(
    prompt: &McpInputPrompt,
    values: &[(String, Value)],
) -> Result<(), &'static str> {
    if values.len() != prompt.fields.len() {
        return Err("input field count mismatch");
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut remaining = iteron_protocol::client_mcp_input::MAX_MCP_INPUT_RESPONSE_BYTES;
    for (id, value) in values {
        if !seen.insert(id) {
            return Err("duplicate input field identity");
        }
        let field = prompt
            .fields
            .iter()
            .find(|field| field.id == *id)
            .ok_or("input field identity mismatch")?;
        remaining = remaining
            .checked_sub(response_value_bytes(value)?)
            .ok_or("input response byte limit reached")?;
        iteron_mcp::validate_mrtr_input(&field.schema, value)
            .map_err(|_| "input response does not match the requested schema")?;
    }
    Ok(())
}
fn prompt_view(prompt: &McpInputPrompt) -> McpInputPromptViewV1 {
    let mut complete = true;
    let fields = prompt
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let schema = scrub_schema(&field.schema, &mut complete);
            McpInputFieldViewV1 {
                field_index: index as u16,
                prompt: iteron_record::redact::scrub(&field.prompt),
                schema,
            }
        })
        .collect();
    McpInputPromptViewV1 {
        request_id: prompt.request_id,
        server_display: iteron_record::redact::scrub(&prompt.server),
        tool_display: iteron_record::redact::scrub(&prompt.tool),
        fields,
        prompt_complete: complete,
    }
}
fn scrub_schema(value: &Value, complete: &mut bool) -> Value {
    match value {
        Value::String(text) => {
            let safe = iteron_record::redact::scrub(text);
            *complete &= safe == *text;
            Value::String(safe)
        }
        Value::Array(values) => {
            Value::Array(values.iter().map(|v| scrub_schema(v, complete)).collect())
        }
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| {
                    let safe = iteron_record::redact::scrub(key);
                    *complete &= safe == *key;
                    (safe, scrub_schema(value, complete))
                })
                .collect(),
        ),
        other => other.clone(),
    }
}
struct RequestLifetime<'a> {
    owner: &'a BridgeHandler,
    id: u64,
}
impl Drop for RequestLifetime<'_> {
    fn drop(&mut self) {
        self.owner.close(self.id, McpInputStateV1::Cancelled);
    }
}
impl McpMrtrHandler for BridgeHandler {
    fn request<'a>(
        &'a self,
        server_name: &'a str,
        tool_name: &'a str,
        request_state: Option<&'a str>,
        requests: Vec<McpInputRequest>,
    ) -> McpFuture<'a, McpInputDecision> {
        Box::pin(async move {
            // The typed MCP request has been validated upstream, but the bridge enforces its own
            // aggregate shape/metadata ceiling before any retained schema or string clone.
            if !request_bounds::requests_fit(server_name, tool_name, request_state, &requests) {
                return Ok(McpInputDecision::Reject);
            }
            let Ok(slot) = self.requests.try_reserve() else {
                return Ok(McpInputDecision::Reject);
            };
            let request_id = self
                .next_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| {
                    iteron_mcp::McpError::Protocol("MCP input correlation id exhausted".into())
                })?;
            let _lifetime = RequestLifetime {
                owner: self,
                id: request_id,
            };
            let (reply, response) = oneshot::channel();
            let prompt = McpInputPrompt {
                request_id,
                server: server_name.to_owned(),
                tool: tool_name.to_owned(),
                request_state: request_state.map(str::to_owned),
                fields: requests
                    .into_iter()
                    .map(|request| McpInputField {
                        id: request.id().to_owned(),
                        prompt: request.prompt().to_owned(),
                        schema: request.schema().clone(),
                    })
                    .collect(),
            };
            let deadline = tokio::time::Instant::now() + MAX_INPUT_WAIT;
            let decision = async {
                slot.send(McpInputRequestEnvelope { prompt, reply });
                response.await.map_err(|_| {
                    iteron_mcp::McpError::Protocol(
                        "interactive MCP input request was not resolved".into(),
                    )
                })
            };
            match tokio::time::timeout_at(deadline, decision).await {
                Ok(decision) => decision,
                Err(_) => {
                    self.close(request_id, McpInputStateV1::TimedOut);
                    Ok(McpInputDecision::Reject)
                }
            }
        })
    }
}
pub(super) struct ServerPort {
    pub(super) requests: mpsc::Receiver<McpInputRequestEnvelope>,
    pub(super) responses: mpsc::Receiver<McpInputResponse>,
    pub(super) handler: Arc<dyn McpMrtrHandler>,
    pub(super) owner: PendingInputs,
}
pub(super) fn wire() -> (mpsc::Sender<McpInputResponse>, ServerPort) {
    let (request_tx, request_rx) = mpsc::channel(capacity());
    let (response_tx, response_rx) = mpsc::channel(capacity());
    let handler = Arc::new(BridgeHandler {
        requests: request_tx,
        next_id: AtomicU64::new(1),
        state: Mutex::new(InputsState::default()),
        changed: Notify::new(),
    });
    (
        response_tx,
        ServerPort {
            requests: request_rx,
            responses: response_rx,
            owner: PendingInputs(handler.clone()),
            handler,
        },
    )
}
pub(super) async fn publish_request(
    envelope: McpInputRequestEnvelope,
    pending: &mut PendingInputs,
    events: &mut EventPublisher,
) {
    if envelope.reply.is_closed() {
        return;
    }
    let request_id = envelope.prompt.request_id;
    if !request_bounds::prompt_fits(&envelope.prompt) {
        let _ = envelope.reply.send(McpInputDecision::Reject);
        return;
    }
    let scope = events
        .contract
        .snapshot()
        .map(|snapshot| (snapshot.thread_id, snapshot.run_id));
    let prompt;
    {
        let mut state = pending.0.lock();
        let cancelled = state
            .pending
            .iter()
            .filter(|(_, entry)| entry.reply.is_closed())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in cancelled {
            if let Some(entry) = state.pending.remove(&id) {
                record_closed(&mut state, id, entry.scope, McpInputStateV1::Cancelled);
            }
        }
        if state.pending.len() >= capacity() || state.pending.contains_key(&request_id) {
            let _ = envelope.reply.send(McpInputDecision::Reject);
            return;
        }
        // Capacity and the original schema bound precede the second presentation clone.
        prompt = envelope.prompt.clone();
        state.revision = state.revision.saturating_add(1);
        state.pending.insert(
            request_id,
            PendingInput {
                prompt: envelope.prompt,
                scope,
                reply: envelope.reply,
            },
        );
        pending.0.changed.notify_waiters();
    }
    if events
        .publish(ServerEvent::McpInputRequested(prompt))
        .await
        .is_err()
    {
        pending.0.close(request_id, McpInputStateV1::Unavailable);
    }
}
pub(super) fn resolve_response(response: McpInputResponse, pending: &mut PendingInputs) -> bool {
    pending.0.resolve(None, response, false).is_ok()
}
pub(super) fn reject_all(pending: &mut PendingInputs) {
    let ids = pending.0.lock().pending.keys().copied().collect::<Vec<_>>();
    for id in ids {
        let _ = pending.0.resolve(
            None,
            McpInputResponse {
                request_id: id,
                answer: McpInputAnswer::Reject,
            },
            false,
        );
    }
}

#[cfg(test)]
#[path = "mcp_input/shared_tests.rs"]
mod shared_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn response_ids_are_correlated_and_stale_answers_are_refused() {
        let (events_tx, mut events_rx) = mpsc::channel(4);
        let mut events = EventPublisher::new(
            events_tx,
            true,
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
        );
        let (reply, decision) = oneshot::channel();
        let envelope = McpInputRequestEnvelope {
            prompt: McpInputPrompt {
                request_id: 7,
                server: "alpha".into(),
                tool: "confirm".into(),
                request_state: Some("round-1".into()),
                fields: vec![McpInputField {
                    id: "profile".into(),
                    prompt: "Choose a profile".into(),
                    schema: serde_json::json!({
                        "type":"object",
                        "properties":{"name":{"type":"string"}},
                        "required":["name"]
                    }),
                }],
            },
            reply,
        };
        let mut pending = PendingInputs::default();
        publish_request(envelope, &mut pending, &mut events).await;
        let published = events_rx.recv().await.unwrap().into_current().unwrap();
        let ServerEvent::McpInputRequested(prompt) = published else {
            panic!("expected MCP input event");
        };
        assert_eq!(prompt.request_id, 7);
        assert_eq!(prompt.request_state.as_deref(), Some("round-1"));
        assert!(!resolve_response(
            McpInputResponse {
                request_id: 8,
                answer: McpInputAnswer::Reject,
            },
            &mut pending,
        ));
        assert!(resolve_response(
            McpInputResponse {
                request_id: 7,
                answer: McpInputAnswer::Approve(vec![(
                    "profile".into(),
                    serde_json::json!({"name":"Alice"}),
                )]),
            },
            &mut pending,
        ));
        assert!(matches!(
            decision.await.unwrap(),
            McpInputDecision::Approve(values)
                if values == vec![("profile".into(), serde_json::json!({"name":"Alice"}))]
        ));
    }

    #[tokio::test]
    async fn cancelled_requests_do_not_consume_bridge_capacity() {
        let (events_tx, _events_rx) = mpsc::channel(MAX_CAPACITY + 1);
        let mut events = EventPublisher::new(
            events_tx,
            true,
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
        );
        let mut pending = PendingInputs::default();
        for request_id in 1..=MAX_CAPACITY as u64 {
            let (reply, decision) = oneshot::channel();
            drop(decision);
            publish_request(
                McpInputRequestEnvelope {
                    prompt: McpInputPrompt {
                        request_id,
                        server: "alpha".into(),
                        tool: "confirm".into(),
                        request_state: None,
                        fields: Vec::new(),
                    },
                    reply,
                },
                &mut pending,
                &mut events,
            )
            .await;
        }
        assert!(pending.is_empty());

        let (reply, _decision) = oneshot::channel();
        publish_request(
            McpInputRequestEnvelope {
                prompt: McpInputPrompt {
                    request_id: MAX_CAPACITY as u64 + 1,
                    server: "alpha".into(),
                    tool: "confirm".into(),
                    request_state: None,
                    fields: Vec::new(),
                },
                reply,
            },
            &mut pending,
            &mut events,
        )
        .await;
        assert_eq!(pending.len(), 1);
    }
}
