use super::super::{AgentEpochV1, AgentIdV1, AgentStateV1, MailboxPort, RuntimeProviderBudgetPort};
use super::*;
use iteron_protocol::agent_control::{AgentMessageKindV1, AgentMessageStateV1};
use iteron_protocol::{Message, ReasoningEffort};
use iteron_provider::TurnRequest;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(in crate::runtime::persistent_agents) struct Port {
    pub(in crate::runtime::persistent_agents) input: AgentMailboxMessage,
    commits: AtomicUsize,
    refuse: AtomicBool,
}
impl MailboxPort for Port {
    fn controller_port(&self) -> Result<Arc<dyn super::super::AgentControlPort>, ControllerError> {
        Err(ControllerError::Permission)
    }
    fn provider_budget_port(
        &self,
        _: AgentIdV1,
        _: AgentEpochV1,
    ) -> Result<Arc<dyn RuntimeProviderBudgetPort>, ControllerError> {
        Err(ControllerError::Permission)
    }
    fn message(&self, id: AgentMessageIdV1) -> Result<AgentMailboxMessage, ControllerError> {
        if id == self.input.id {
            Ok(self.input.clone())
        } else {
            Err(ControllerError::UnknownMessage)
        }
    }
    fn deliver(
        &self,
        _: AgentIdV1,
        _: AgentEpochV1,
    ) -> Result<Vec<AgentMailboxMessage>, ControllerError> {
        Ok(Vec::new())
    }
    fn consumed(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        ids: &[AgentMessageIdV1],
    ) -> Result<(), ControllerError> {
        assert_eq!(id, self.input.receiver);
        assert_eq!(self.input.state, AgentMessageStateV1::Delivered { epoch });
        assert_eq!(ids, &[self.input.id]);
        if self.refuse.load(Ordering::SeqCst) {
            return Err(ControllerError::RecoveryRequired);
        }
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn state(&self, _: AgentIdV1) -> Result<AgentStateV1, ControllerError> {
        Ok(AgentStateV1::Running {
            epoch: AgentEpochV1 {
                incarnation: 3,
                turn: 4,
            },
        })
    }
}
pub(in crate::runtime::persistent_agents) fn mailbox() -> (LiveAgentMailbox, Arc<Port>) {
    mailbox_with_sender(None)
}
pub(in crate::runtime::persistent_agents) fn mailbox_with_sender(
    sender: Option<AgentIdV1>,
) -> (LiveAgentMailbox, Arc<Port>) {
    let epoch = AgentEpochV1 {
        incarnation: 3,
        turn: 4,
    };
    let text = "native input canary 中文";
    let port = Arc::new(Port {
        input: AgentMailboxMessage {
            id: AgentMessageIdV1(19),
            sender,
            receiver: AgentIdV1(7),
            sequence: 1,
            kind: AgentMessageKindV1::Message,
            state: AgentMessageStateV1::Delivered { epoch },
            text: Some(text.into()),
            content_sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
            expected_epoch: None,
        },
        commits: AtomicUsize::new(0),
        refuse: AtomicBool::new(false),
    });
    (
        LiveAgentMailbox {
            id: port.input.receiver,
            epoch,
            port: port.clone(),
            witnesses: Arc::new(Mutex::new(MailboxWitnesses::default())),
            deferred: Arc::new(Mutex::new(Vec::new())),
        },
        port,
    )
}
fn request(messages: Vec<Message>) -> TurnRequest {
    TurnRequest {
        model: "fixture".into(),
        system: "system".into(),
        messages,
        input_images: Vec::new(),
        tools: Vec::new().into(),
        max_tokens: 64,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: ReasoningEffort::Low,
        controls: Default::default(),
    }
}
fn prove(
    mailbox: &LiveAgentMailbox,
    adapter: AdapterKind,
    request: &TurnRequest,
    body: &Value,
) -> Result<PreparedMailboxDelivery, RequestCaptureError> {
    let bytes = serde_json::to_vec(body).unwrap();
    mailbox.prepared_delivery(&ProviderWireRequest {
        adapter,
        method: "POST",
        endpoint: "https://fixture.invalid",
        content_type: "application/json",
        body: &bytes,
        serialized_output_tokens: 64,
        request,
    })
}

#[test]
fn native_exact_user_fields_cover_all_three_adapter_projections() {
    for adapter in [
        AdapterKind::AnthropicMessages,
        AdapterKind::OpenAiResponses,
        AdapterKind::OpenAiCompatibleChat,
    ] {
        let (mailbox, port) = mailbox();
        let envelope = mailbox.render(&port.input).unwrap();
        let request = request(vec![Message {
            role: Role::User,
            content: vec![
                Block::Text {
                    text: "operator task\n\n".into(),
                },
                Block::Text {
                    text: envelope.clone(),
                },
            ],
        }]);
        let body = match adapter {
            AdapterKind::AnthropicMessages => {
                serde_json::json!({"messages":[{"role":"user","content":[{"type":"text","text":envelope}]}]})
            }
            AdapterKind::OpenAiResponses => {
                serde_json::json!({"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":envelope}]}]})
            }
            AdapterKind::OpenAiCompatibleChat => {
                serde_json::json!({"messages":[{"role":"user","content":format!("operator task\n\n{envelope}")}]})
            }
        };
        let proof = prove(&mailbox, adapter, &request, &body).unwrap();
        assert_eq!(
            port.commits.load(Ordering::SeqCst),
            0,
            "preparation alone does not append Consumed"
        );
        mailbox.confirm_prepared(proof).unwrap();
        assert_eq!(port.commits.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn semantic_selection_wrong_role_nested_tool_and_substrings_are_not_native_inclusion() {
    for placement in [
        "assistant",
        "system",
        "tool",
        "substring",
        "nested",
        "omitted",
    ] {
        let (mailbox, port) = mailbox();
        let envelope = mailbox.render(&port.input).unwrap();
        let request = request(vec![Message::user_text(envelope.clone())]);
        let body = match placement {
            "assistant" | "system" | "tool" => {
                serde_json::json!({"messages":[{"role":placement,"content":envelope}]})
            }
            "substring" => {
                serde_json::json!({"messages":[{"role":"user","content":format!("prefix {envelope} suffix")}]})
            }
            "nested" => {
                serde_json::json!({"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":envelope}]}]}]})
            }
            _ => {
                serde_json::json!({"messages":[{"role":"user","content":"omitted"}],"metadata":{"payload":envelope}})
            }
        };
        assert!(
            matches!(
                prove(&mailbox, AdapterKind::OpenAiCompatibleChat, &request, &body),
                Err(RequestCaptureError::Unavailable)
            ),
            "{placement}"
        );
        assert_eq!(port.commits.load(Ordering::SeqCst), 0);
        assert!(mailbox.refuse_unsupported_pending().is_err());
    }
}

#[test]
fn joined_initial_and_real_steer_wrappers_have_explicit_host_receipts() {
    for steer in [false, true] {
        let (mailbox, port) = mailbox();
        let text = if steer {
            steer_text(&mailbox.render_steer(&port.input).unwrap())
        } else {
            mailbox
                .render_initial(std::slice::from_ref(&port.input))
                .unwrap()
        };
        let request = request(vec![Message::user_text(text.clone())]);
        let body = serde_json::json!({"input":[{"role":"user","content":[{"type":"input_text","text":text}]}]});
        mailbox
            .confirm_prepared(
                prove(&mailbox, AdapterKind::OpenAiResponses, &request, &body).unwrap(),
            )
            .unwrap();
        assert_eq!(port.commits.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn concurrent_hedge_proofs_commit_once_and_refusal_preserves_witness() {
    let (mailbox, port) = mailbox();
    let envelope = mailbox.render(&port.input).unwrap();
    let request = request(vec![Message::user_text(envelope.clone())]);
    let body = serde_json::json!({"messages":[{"role":"user","content":envelope}]});
    port.refuse.store(true, Ordering::SeqCst);
    assert!(
        mailbox
            .confirm_prepared(
                prove(&mailbox, AdapterKind::OpenAiCompatibleChat, &request, &body).unwrap()
            )
            .is_err()
    );
    assert_eq!(mailbox.witnesses.lock().unwrap().envelopes.len(), 1);
    assert_eq!(port.commits.load(Ordering::SeqCst), 0);
    port.refuse.store(false, Ordering::SeqCst);
    let first = prove(&mailbox, AdapterKind::OpenAiCompatibleChat, &request, &body).unwrap();
    let second = prove(&mailbox, AdapterKind::OpenAiCompatibleChat, &request, &body).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| mailbox.confirm_prepared(first).unwrap());
        scope.spawn(|| mailbox.confirm_prepared(second).unwrap());
    });
    assert_eq!(port.commits.load(Ordering::SeqCst), 1);
    assert!(mailbox.refuse_unsupported_pending().is_ok());
}

#[test]
fn receipt_cannot_cross_mailbox_owner_even_with_identical_public_ids_and_text() {
    let (first, port) = mailbox();
    let (second, second_port) = mailbox();
    let envelope = first.render(&port.input).unwrap();
    second.render(&second_port.input).unwrap();
    let request = request(vec![Message::user_text(envelope.clone())]);
    let body = serde_json::json!({"messages":[{"role":"user","content":envelope}]});
    let proof = prove(&first, AdapterKind::OpenAiCompatibleChat, &request, &body).unwrap();
    assert!(matches!(
        second.confirm_prepared(proof),
        Err(ControllerError::Permission)
    ));
    assert_eq!(second_port.commits.load(Ordering::SeqCst), 0);
}
