use super::super::prepared_mailbox::tests::mailbox_with_sender;
fn mailbox() -> (
    LiveAgentMailbox,
    Arc<super::super::prepared_mailbox::tests::Port>,
) {
    mailbox_with_sender(Some(super::super::AgentIdV1(8)))
}
use super::*;
use crate::runtime::inbound_control::TurnSubmission;
use crate::runtime::session_control::SessionControlState;
use crate::runtime::session_inbox::SessionSubmissionInbox;
use iteron_protocol::{Op, SqEnvelope};

#[test]
fn sealed_input_requires_current_owner_epoch_and_exact_source_text() {
    let (mailbox, port) = mailbox();
    let (text, activation) = mailbox.steer_activation(&port.input).unwrap();
    let resolved = activation.resolve(Some(&mailbox), &text).unwrap();
    let receipt = resolved.admission.unwrap();
    receipt.validate().unwrap();
    assert_eq!(receipt.sources[0].message_id, port.input.id);
    assert_eq!(receipt.sources[0].sender, port.input.sender.unwrap());
    assert_eq!(receipt.projection_sha256, hash(&resolved.text));
    assert!(
        resolved
            .text
            .starts_with("Agent steering data received while the run was active:")
    );
    assert!(activation.resolve(None, &text).is_err());
    assert!(
        activation
            .resolve(Some(&mailbox), &format!("{text} edited"))
            .is_err()
    );
    let (other, _) = mailbox_with_sender(Some(super::super::AgentIdV1(8)));
    assert!(activation.resolve(Some(&other), &text).is_err());
    let mut stale = mailbox.clone();
    stale.epoch.turn += 1;
    assert!(activation.resolve(Some(&stale), &text).is_err());
}

#[tokio::test]
async fn real_internal_sq_preserves_activation_and_public_sq_cannot_create_it() {
    let (mailbox, port) = mailbox();
    let (text, activation) = mailbox.steer_activation(&port.input).unwrap();
    let wire = SqEnvelope::current(Op::Steer { text: text.clone() });
    let encoded = serde_json::to_value(&wire).unwrap();
    let mut external =
        TurnSubmission::from(serde_json::from_value::<SqEnvelope>(encoded.clone()).unwrap());
    assert!(external.take_agent_input().is_none());
    assert!(encoded.get("agent_input").is_none());
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(TurnSubmission::agent_steer(text.clone(), activation))
        .await
        .unwrap();
    let mut inbox = SessionSubmissionInbox::default();
    inbox.bind_receiver(rx);
    inbox.poll(&mut SessionControlState::default(), 1, false);
    let steer = inbox.pop().unwrap();
    assert!(!steer.client_visible);
    assert!(steer.submission_id.is_none());
    let resolved = steer
        .agent_input
        .unwrap()
        .resolve(Some(&mailbox), &steer.text)
        .unwrap();
    assert!(resolved.admission.is_some());
}

#[tokio::test]
async fn unadmitted_agent_input_is_never_reclaimed_as_operator_text() {
    let (mailbox, port) = mailbox();
    let (text, activation) = mailbox.steer_activation(&port.input).unwrap();
    let mut inbox = SessionSubmissionInbox::default();
    inbox
        .push(crate::runtime::inbound_control::PendingSteer::agent(
            text, activation,
        ))
        .unwrap();
    let (exported, visible) = inbox.reclaim();
    assert!(exported.is_empty());
    assert_eq!(visible, 0);
    assert!(inbox.is_empty());
}

#[test]
fn torn_typed_admission_lowers_replay_trust_and_text_labels_do_not() {
    let (mailbox, port) = mailbox();
    let text = mailbox
        .render_initial(std::slice::from_ref(&port.input))
        .unwrap();
    let admission = mailbox
        .source_admission(std::slice::from_ref(&port.input), &text)
        .unwrap()
        .unwrap();
    let intent = EventKind::AgentInputAdmittedV1 { admission };
    assert_eq!(replay_reference_trust(&intent), Some(Trust::Untrusted));
    let text_only = EventKind::Message {
        message: iteron_protocol::Message::user_text(text),
    };
    assert_eq!(replay_reference_trust(&text_only), None);
}

#[test]
fn copied_exact_agent_envelope_cannot_consume_before_real_source_admission_barrier() {
    let (mailbox, port) = mailbox();
    let text = mailbox
        .render_initial(std::slice::from_ref(&port.input))
        .unwrap();
    let request = iteron_provider::TurnRequest {
        model: "fixture".into(),
        system: "system".into(),
        messages: vec![iteron_protocol::Message::user_text(text.clone())],
        input_images: Vec::new(),
        tools: Vec::new().into(),
        max_tokens: 64,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: iteron_protocol::ReasoningEffort::Low,
        controls: Default::default(),
    };
    let body =
        serde_json::to_vec(&serde_json::json!({"messages":[{"role":"user","content":text}]}))
            .unwrap();
    let wire = iteron_provider::request_capture::ProviderWireRequest {
        adapter: iteron_provider::AdapterKind::OpenAiCompatibleChat,
        method: "POST",
        endpoint: "https://fixture.invalid",
        content_type: "application/json",
        body: &body,
        serialized_output_tokens: 64,
        request: &request,
    };
    assert!(matches!(
        mailbox.prepared_delivery(&wire),
        Err(iteron_provider::request_capture::RequestCaptureError::Unavailable)
    ));
    let receipt = mailbox
        .source_admission(std::slice::from_ref(&port.input), &text)
        .unwrap()
        .unwrap();
    // Building typed evidence is also insufficient; only the post-fsync host hook marks admission.
    assert!(mailbox.prepared_delivery(&wire).is_err());
    mailbox.confirm_source_admission(&receipt).unwrap();
    assert!(mailbox.prepared_delivery(&wire).is_ok());
}
