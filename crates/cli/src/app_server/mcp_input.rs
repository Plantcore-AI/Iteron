//! Bounded 2026 MCP input bridge between the runtime-owned client and an interactive frontend.

use super::{EventPublisher, ServerEvent};
use iteron_mcp::{McpFuture, McpInputDecision, McpInputRequest, McpMrtrHandler};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{mpsc, oneshot};

pub(crate) const MAX_CAPACITY: usize = 8;

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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct McpInputPrompt {
    pub(crate) request_id: u64,
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) request_state: Option<String>,
    pub(crate) fields: Vec<McpInputField>,
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

struct BridgeHandler {
    requests: mpsc::Sender<McpInputRequestEnvelope>,
    next_id: AtomicU64,
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
            let request_id = self
                .next_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| {
                    iteron_mcp::McpError::Protocol("MCP input correlation id exhausted".into())
                })?;
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
            self.requests
                .send(McpInputRequestEnvelope { prompt, reply })
                .await
                .map_err(|_| {
                    iteron_mcp::McpError::Protocol(
                        "interactive MCP input frontend is unavailable".into(),
                    )
                })?;
            response.await.map_err(|_| {
                iteron_mcp::McpError::Protocol(
                    "interactive MCP input request was not resolved".into(),
                )
            })
        })
    }
}

pub(super) struct ServerPort {
    pub(super) requests: mpsc::Receiver<McpInputRequestEnvelope>,
    pub(super) responses: mpsc::Receiver<McpInputResponse>,
    pub(super) handler: Arc<dyn McpMrtrHandler>,
}

pub(super) fn wire() -> (mpsc::Sender<McpInputResponse>, ServerPort) {
    let capacity = capacity();
    let (request_tx, request_rx) = mpsc::channel(capacity);
    let (response_tx, response_rx) = mpsc::channel(capacity);
    let handler = Arc::new(BridgeHandler {
        requests: request_tx,
        next_id: AtomicU64::new(1),
    });
    (
        response_tx,
        ServerPort {
            requests: request_rx,
            responses: response_rx,
            handler,
        },
    )
}

pub(super) async fn publish_request(
    envelope: McpInputRequestEnvelope,
    pending: &mut BTreeMap<u64, oneshot::Sender<McpInputDecision>>,
    events: &mut EventPublisher,
) {
    pending.retain(|_, reply| !reply.is_closed());
    if envelope.reply.is_closed() {
        return;
    }
    if pending.len() >= capacity() || pending.contains_key(&envelope.prompt.request_id) {
        let _ = envelope.reply.send(McpInputDecision::Reject);
        return;
    }
    let request_id = envelope.prompt.request_id;
    if events
        .publish(ServerEvent::McpInputRequested(envelope.prompt))
        .await
        .is_ok()
    {
        pending.insert(request_id, envelope.reply);
    } else {
        let _ = envelope.reply.send(McpInputDecision::Reject);
    }
}

pub(super) fn resolve_response(
    response: McpInputResponse,
    pending: &mut BTreeMap<u64, oneshot::Sender<McpInputDecision>>,
) -> bool {
    let Some(reply) = pending.remove(&response.request_id) else {
        return false;
    };
    let decision = match response.answer {
        McpInputAnswer::Approve(values) => McpInputDecision::Approve(values),
        McpInputAnswer::Reject => McpInputDecision::Reject,
    };
    reply.send(decision).is_ok()
}

pub(super) fn reject_all(pending: &mut BTreeMap<u64, oneshot::Sender<McpInputDecision>>) {
    for (_, reply) in std::mem::take(pending) {
        let _ = reply.send(McpInputDecision::Reject);
    }
}

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
        let mut pending = BTreeMap::new();
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
        let mut pending = BTreeMap::new();
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
