//! Fixture-only native input inclusion. Exercises the real mailbox proof path without a
//! transport; this is not provider, retained-manifest or remote-consumption evidence.
use super::LiveAgentMailbox;
use iteron_agents::AgentMailboxMessage;
use iteron_protocol::{Event, EventKind, Message, ReasoningEffort, Seq, TurnId};
use iteron_provider::request_capture::ProviderWireRequest;
use iteron_provider::{AdapterKind, TurnRequest};
use iteron_record::Rollout;

impl LiveAgentMailbox {
    pub(crate) fn confirm_fixture_native_input(
        &self,
        initial: &[AgentMailboxMessage],
        rollout: Option<&mut Rollout>,
    ) -> Result<(), String> {
        let text = self.render_initial(initial).map_err(|e| e.to_string())?;
        if let Some(admission) = self
            .source_admission(initial, &text)
            .map_err(|e| e.to_string())?
        {
            let rollout = rollout.ok_or("sourced fixture input requires its actual WAL")?;
            let turn = TurnId(
                u32::try_from(self.epoch.turn).map_err(|_| "fixture turn exceeds record range")?,
            );
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn,
                    kind: EventKind::AgentInputAdmittedV1 {
                        admission: admission.clone(),
                    },
                })
                .map_err(|e| e.to_string())?;
            self.confirm_source_admission(&admission)
                .map_err(|e| e.to_string())?;
        }
        let request = TurnRequest {
            model: "fixture-native-input".into(),
            system: String::new(),
            messages: vec![Message::user_text(text.clone())],
            input_images: Vec::new(),
            tools: Vec::new().into(),
            max_tokens: 1,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: ReasoningEffort::Low,
            controls: Default::default(),
        };
        let body = serde_json::to_vec(&serde_json::json!({
            "model": request.model,
            "max_output_tokens": request.max_tokens,
            "input": [{"role": "user", "content": [{"type": "input_text", "text": text}]}]
        }))
        .map_err(|e| e.to_string())?;
        let proof = self
            .prepared_delivery(&ProviderWireRequest {
                adapter: AdapterKind::OpenAiResponses,
                method: "POST",
                endpoint: "https://fixture.invalid/v1/responses",
                content_type: "application/json",
                body: &body,
                serialized_output_tokens: request.max_tokens,
                request: &request,
            })
            .map_err(|e| format!("{e:?}"))?;
        self.confirm_prepared(proof).map_err(|e| e.to_string())
    }
}
