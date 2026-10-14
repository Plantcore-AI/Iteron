//! Ark's Chat continuation is not the portable thinking projection. The exact official roots
//! share a documented protocol; a vendor-looking model name or gateway host is not sufficient.
//! https://docs.volcengine.com/docs/ark/deep-thinking?lang=en
//! https://docs.volcengine.com/docs/ark/integrate-third-party-tools?lang=zh
//! https://docs.volcengine.com/docs/ark/chat-api?lang=zh&redirect=1

use super::{ApiRoot, Block, Code, Field, ProviderError, ProviderState, invalid};
use iteron_protocol::Message;
use serde_json::{Value, json};

const FORMAT: &str = "ark.chat.thinking.v1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ArkRoute {
    Standard,
    AgentPlan,
    CodingPlan,
}

impl ArkRoute {
    pub(super) fn for_root(root: Option<&ApiRoot>) -> Option<Self> {
        match root.map(ApiRoot::as_str) {
            Some("https://ark.cn-beijing.volces.com/api/v3") => Some(Self::Standard),
            Some("https://ark.cn-beijing.volces.com/api/plan/v3") => Some(Self::AgentPlan),
            Some("https://ark.cn-beijing.volces.com/api/coding/v3") => Some(Self::CodingPlan),
            _ => None,
        }
    }

    fn root(self) -> &'static str {
        match self {
            Self::Standard => "https://ark.cn-beijing.volces.com/api/v3",
            Self::AgentPlan => "https://ark.cn-beijing.volces.com/api/plan/v3",
            Self::CodingPlan => "https://ark.cn-beijing.volces.com/api/coding/v3",
        }
    }
}

fn state_limit() -> usize {
    iteron_tunables::param_integer(
        "provider.openai.max_reasoning_state_payload_bytes",
        super::MAX_REASONING_STATE_PAYLOAD_BYTES,
    )
    .min(super::MAX_REASONING_STATE_PAYLOAD_BYTES)
}

/// No Debug: encrypted provider state is never an operator-facing diagnostic or text delta.
#[derive(Default)]
pub(super) struct StreamState {
    encrypted: String,
    reasoning_bytes: usize,
}

fn fragment<'a>(
    delta: Option<&'a Value>,
    key: &str,
    field: Field,
) -> Result<Option<&'a str>, ProviderError> {
    match delta.and_then(|value| value.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(invalid(Code::InvalidType, field)),
    }
}

pub(super) fn validate_reasoning_delta(delta: Option<&Value>) -> Result<(), ProviderError> {
    fragment(delta, "reasoning_content", Field::ChatReasoningContent).map(|_| ())
}

impl StreamState {
    fn check_size(&self, additional: usize, field: Field) -> Result<(), ProviderError> {
        if self
            .encrypted
            .len()
            .checked_add(self.reasoning_bytes)
            .and_then(|length| length.checked_add(additional))
            .is_none_or(|length| length > state_limit())
        {
            return Err(invalid(Code::LimitExceeded, field));
        }
        Ok(())
    }

    pub(super) fn observe_encrypted(
        &mut self,
        delta: Option<&Value>,
    ) -> Result<usize, ProviderError> {
        let Some(text) = fragment(delta, "encrypted_content", Field::ChatEncryptedContent)? else {
            return Ok(0);
        };
        if text.is_empty() {
            return Ok(0);
        }
        // Ark specifies a complete encrypted value in a separate delta, not incremental
        // ciphertext. Repeated identical values are harmless; concatenating or replacing a
        // conflicting value would corrupt the signature. TCP/SSE fragmentation is handled by
        // the wire parser before this point.
        if !self.encrypted.is_empty() {
            return if self.encrypted == text {
                Ok(0)
            } else {
                Err(invalid(Code::ConflictingValue, Field::ChatEncryptedContent))
            };
        }
        self.check_size(text.len(), Field::ChatEncryptedContent)?;
        self.encrypted.push_str(text);
        Ok(text.len())
    }

    pub(super) fn append_reasoning_len(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.check_size(bytes, Field::ChatReasoningContent)?;
        self.reasoning_bytes += bytes;
        Ok(())
    }

    pub(super) fn finish(
        self,
        scope: &str,
        route: ArkRoute,
        model: &str,
        reasoning: &str,
    ) -> Result<Option<ProviderState>, ProviderError> {
        if self.encrypted.is_empty() && reasoning.is_empty() {
            return Ok(None);
        }
        super::validate_chat_route_scope(scope)?;
        validate_model(model)?;
        let mut payload = json!({"api_root":route.root(),"model":model});
        if !reasoning.is_empty() {
            payload["reasoning_content"] = Value::String(reasoning.to_owned());
        }
        if !self.encrypted.is_empty() {
            payload["encrypted_content"] = Value::String(self.encrypted);
        }
        validate_payload(&payload)?;
        Ok(Some(ProviderState {
            route_scope: scope.to_owned(),
            format: FORMAT.into(),
            payload,
        }))
    }
}

fn validate_model(model: &str) -> Result<(), ProviderError> {
    if model.is_empty()
        || model.len() > super::MAX_ROUTE_SCOPE_BYTES
        || model.chars().any(char::is_control)
    {
        return Err(invalid(Code::InvalidValue, Field::Response));
    }
    Ok(())
}

fn validate_payload(payload: &Value) -> Result<(), ProviderError> {
    let object = payload
        .as_object()
        .ok_or_else(|| invalid(Code::InvalidType, Field::Response))?;
    if !(3..=4).contains(&object.len())
        || object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "api_root" | "model" | "reasoning_content" | "encrypted_content"
            )
        })
    {
        return Err(invalid(Code::InvalidValue, Field::Response));
    }
    let root = object
        .get("api_root")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(Code::InvalidType, Field::Response))?;
    if ![
        ArkRoute::Standard,
        ArkRoute::AgentPlan,
        ArkRoute::CodingPlan,
    ]
    .iter()
    .any(|route| route.root() == root)
    {
        return Err(invalid(Code::InvalidValue, Field::Response));
    }
    validate_model(
        object
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(Code::InvalidType, Field::Response))?,
    )?;
    for key in ["reasoning_content", "encrypted_content"] {
        if let Some(value) = object.get(key) {
            let text = value
                .as_str()
                .ok_or_else(|| invalid(Code::InvalidType, Field::Response))?;
            if text.is_empty() {
                return Err(invalid(Code::InvalidValue, Field::Response));
            }
            if text.len() > state_limit() {
                return Err(invalid(Code::LimitExceeded, Field::Response));
            }
        }
    }
    if serde_json::to_vec(payload)
        .map_err(|_| invalid(Code::InvalidValue, Field::Response))?
        .len()
        > state_limit()
    {
        return Err(invalid(Code::LimitExceeded, Field::Response));
    }
    Ok(())
}

pub(super) fn replay(
    message: &Message,
    scope: &str,
    route: ArkRoute,
    model: &str,
    assistant: &mut Value,
) -> Result<(), ProviderError> {
    let mut found = false;
    for block in &message.content {
        let Block::ProviderState(state) = block else {
            continue;
        };
        if state.route_scope != scope {
            continue;
        }
        if state.format == super::OPENAI_CHAT_REASONING_FORMAT {
            // Older explicitly profiled Ark routes could retain generic plaintext state.
            // It has no endpoint/model binding, so neither silently discard nor rebind it.
            return Err(ProviderError::Configuration(
                "legacy Ark reasoning state has no endpoint/model binding; start a fresh session"
                    .into(),
            ));
        }
        if state.format != FORMAT {
            continue;
        }
        if found {
            return Err(invalid(Code::ConflictingValue, Field::Response));
        }
        validate_payload(&state.payload)?;
        if state.payload["api_root"].as_str() != Some(route.root())
            || state.payload["model"].as_str() != Some(model)
        {
            return Err(ProviderError::Configuration(
                "Ark continuation state does not match the configured endpoint and model".into(),
            ));
        }
        found = true;
        for key in ["reasoning_content", "encrypted_content"] {
            if let Some(value) = state.payload.get(key) {
                assistant[key] = value.clone();
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "ark_thinking_tests.rs"]
mod tests;
