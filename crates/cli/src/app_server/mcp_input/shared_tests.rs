use super::super::mcp_input_public::execute;
use super::*;
use iteron_protocol::client_mcp_input::{
    McpInputActionV1, McpInputAnswerV1, McpInputCommandV1, McpInputValueV1,
};
use serde_json::json;

fn events() -> (EventPublisher, mpsc::Receiver<super::super::EventEnvelope>) {
    let (tx, rx) = mpsc::channel(16);
    let mut events = EventPublisher::new(
        tx,
        true,
        iteron_obs::lifecycle::LifecycleEmitter::new(iteron_obs::lifecycle::LifecycleBus::default()),
    );
    events.bind_lifecycle_identity(SessionId("session-run".into()), RunId("run".into()));
    (events, rx)
}
fn form(id: u64) -> (McpInputRequestEnvelope, oneshot::Receiver<McpInputDecision>) {
    let (reply, receive) = oneshot::channel();
    (
        McpInputRequestEnvelope {
            prompt: McpInputPrompt {
                request_id: id,
                server: "alpha".into(),
                tool: "choose".into(),
                request_state: Some("private-continuation-state".into()),
                fields: vec![McpInputField {
                    id: "opaque-private-field".into(),
                    prompt: "Choose a label".into(),
                    schema: json!({"type":"object","properties":{"label":{"type":"string"}},"required":["label"]}),
                }],
            },
            reply,
        },
        receive,
    )
}
fn command(action: McpInputActionV1) -> McpInputCommandV1 {
    McpInputCommandV1 {
        thread_id: SessionId("session-run".into()),
        run_id: RunId("run".into()),
        command: action,
    }
}
fn approve(id: u64, value: Value) -> McpInputActionV1 {
    McpInputActionV1::Respond {
        request_id: id,
        answer: McpInputAnswerV1::Approve {
            values: vec![McpInputValueV1 {
                field_index: 0,
                content: value,
            }],
        },
    }
}
#[tokio::test]
async fn actual_callback_payload_is_once_only_and_absent_from_every_observation() {
    let (mut events, mut eq) = events();
    let (_responses, wire) = wire();
    let mut inputs = wire.owner;
    events.contract.bind_mcp_input_owner(inputs.clone());
    let gate = Arc::new(tokio::sync::RwLock::new(()));
    events.contract.bind_mcp_input_gate_for_test(gate);
    let (request, decision) = form(7);
    publish_request(request, &mut inputs, &mut events).await;
    let observed = eq.recv().await.unwrap().into_current().unwrap();
    assert!(matches!(observed, ServerEvent::McpInputRequested(_)));
    let snapshot = execute(events.contract.clone(), command(McpInputActionV1::Read {})).await;
    assert_eq!(
        snapshot["snapshot"]["pending"][0]["fields"][0]["field_index"],
        0
    );
    let rendered = snapshot.to_string();
    assert!(
        !rendered.contains("opaque-private-field")
            && !rendered.contains("private-continuation-state")
    );
    let bad = execute(
        events.contract.clone(),
        command(approve(7, json!({"other":"private-value"}))),
    )
    .await;
    assert_eq!(bad["type"], "mcp_input_refused_v1");
    assert_eq!(inputs.len(), 1);
    let response = execute(
        events.contract.clone(),
        command(approve(7, json!({"label":"private-value"}))),
    )
    .await;
    assert_eq!(response["state"], "answered");
    assert!(!response.to_string().contains("private-value"));
    assert!(
        matches!(decision.await.unwrap(), McpInputDecision::Approve(values) if values==vec![("opaque-private-field".into(),json!({"label":"private-value"}))])
    );
    let duplicate = execute(
        events.contract.clone(),
        command(approve(7, json!({"label":"second-value"}))),
    )
    .await;
    assert_eq!(duplicate["type"], "mcp_input_refused_v1");
    let view = inputs.snapshot(&SessionId("session-run".into()), &RunId("run".into()));
    assert!(view.pending.is_empty());
    assert_eq!(view.closed.len(), 1);
    let serialized = serde_json::to_string(&view).unwrap();
    assert!(!serialized.contains("private-value") && !serialized.contains("second-value"));
    assert!(
        eq.try_recv().is_err(),
        "responding cannot publish response values into the EQ"
    );
}
#[tokio::test]
async fn actual_adoption_gate_and_request_origin_precede_response_side_effects() {
    let (mut events, _eq) = events();
    let mut inputs = PendingInputs::default();
    events.contract.bind_mcp_input_owner(inputs.clone());
    let gate = Arc::new(tokio::sync::RwLock::new(()));
    events.contract.bind_mcp_input_gate_for_test(gate.clone());
    let (request, mut decision) = form(9);
    publish_request(request, &mut inputs, &mut events).await;
    let adopt = gate.clone().write_owned().await;
    let reply = execute(
        events.contract.clone(),
        command(approve(9, json!({"label":"private-value"}))),
    )
    .await;
    assert_eq!(reply["reason_code"], "adoption_pending");
    assert!(matches!(
        decision.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    events.bind_lifecycle_identity(SessionId("session-new".into()), RunId("new".into()));
    drop(adopt);
    let reply = execute(
        events.contract.clone(),
        command(approve(9, json!({"label":"private-value"}))),
    )
    .await;
    assert_eq!(reply["reason_code"], "scope_mismatch");
    let forged = McpInputCommandV1 {
        thread_id: SessionId("session-new".into()),
        run_id: RunId("new".into()),
        command: approve(9, json!({"label":"private-value"})),
    };
    let reply = execute(events.contract.clone(), forged).await;
    assert_eq!(reply["reason_code"], "request_not_pending");
    assert!(matches!(
        decision.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(inputs.len(), 1);
}
#[tokio::test]
async fn dropping_the_real_handler_future_closes_the_same_callback_owner() {
    let (mut events, _eq) = events();
    let (_response, mut port) = wire();
    let handler = port.handler.clone();
    let task = tokio::spawn(async move {
        handler
            .request("alpha", "choose", Some("round"), Vec::new())
            .await
    });
    let envelope = tokio::time::timeout(Duration::from_secs(1), port.requests.recv())
        .await
        .unwrap()
        .unwrap();
    let id = envelope.prompt.request_id;
    publish_request(envelope, &mut port.owner, &mut events).await;
    let before = port
        .owner
        .snapshot(&SessionId("session-run".into()), &RunId("run".into()));
    assert_eq!(before.pending.len(), 1);
    task.abort();
    let _ = task.await;
    let after = port
        .owner
        .wait(
            &SessionId("session-run".into()),
            &RunId("run".into()),
            before.revision,
            1,
        )
        .await;
    assert!(after.pending.is_empty());
    assert!(
        after
            .closed
            .iter()
            .any(|closed| closed.request_id == id && closed.state == McpInputStateV1::Cancelled)
    );
    assert!(!resolve_response(
        McpInputResponse {
            request_id: id,
            answer: McpInputAnswer::Reject
        },
        &mut port.owner
    ));
}
#[tokio::test]
async fn changed_schema_projection_cannot_authorize_a_response_but_reject_is_available() {
    let (mut events, _eq) = events();
    let mut inputs = PendingInputs::default();
    events.contract.bind_mcp_input_owner(inputs.clone());
    events
        .contract
        .bind_mcp_input_gate_for_test(Arc::new(tokio::sync::RwLock::new(())));
    let (mut request, decision) = form(11);
    request.prompt.fields[0].schema["properties"]["label"]["default"] =
        json!("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789");
    publish_request(request, &mut inputs, &mut events).await;
    let view = inputs.snapshot(&SessionId("session-run".into()), &RunId("run".into()));
    assert!(!view.pending[0].prompt_complete);
    assert!(
        !serde_json::to_string(&view)
            .unwrap()
            .contains("abcdefghijklmnopqrstuvwxyz0123456789")
    );
    let reply = execute(
        events.contract.clone(),
        command(approve(11, json!({"label":"safe"}))),
    )
    .await;
    assert_eq!(reply["type"], "mcp_input_refused_v1");
    let reply = execute(
        events.contract.clone(),
        command(McpInputActionV1::Respond {
            request_id: 11,
            answer: McpInputAnswerV1::Reject {},
        }),
    )
    .await;
    assert_eq!(reply["state"], "rejected");
    assert!(matches!(decision.await.unwrap(), McpInputDecision::Reject));
}
