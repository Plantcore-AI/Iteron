//! Language-neutral process protocol for replaceable optimization implementations.
//!
//! The marketplace admits bytes and prepares a process launch; this module defines the bounded
//! JSON messages exchanged after launch. The provider may return decisions and observations, but
//! it never receives activation, promotion, permission, budget, or evidence authority.

use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::{
    ContractRef, ModuleId, capability_seam_graph, validate_capability_seam_graph,
};
use serde::{Deserialize, Serialize};

pub const IMPLEMENTATION_PROTOCOL: &str = "iteron-implementation/1";
pub const MAX_IMPLEMENTATION_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_IMPLEMENTATION_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_PROTOCOL_ID_BYTES: usize = 128;
const MAX_FAILURE_MESSAGE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImplementationRequest {
    Load {
        lifecycle_contract: ContractRef,
        definition_contract: ContractRef,
        provider_contract: ContractRef,
        consumer_contract: ContractRef,
        observation_schema: ContractRef,
        artifact_sha256: String,
        admitted_capabilities: CapabilitySet,
    },
    Start {
        lifecycle_contract: ContractRef,
        run_id: String,
        candidate_sha256: String,
        input_schema: ContractRef,
        input: serde_json::Value,
        deadline_ms: u64,
    },
    Cancel {
        lifecycle_contract: ContractRef,
        run_id: String,
        reason: String,
    },
    Stop {
        lifecycle_contract: ContractRef,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationRequestEnvelope {
    pub protocol: String,
    pub request_id: String,
    pub implementation_id: String,
    pub module: ModuleId,
    pub payload: ImplementationRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImplementationResponse {
    Loaded {
        provider_contract: ContractRef,
        observation_schema: ContractRef,
    },
    Started {
        run_id: String,
    },
    Cancelled {
        run_id: String,
    },
    Stopped,
    Failed {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationResponseEnvelope {
    pub protocol: String,
    pub request_id: String,
    pub implementation_id: String,
    pub module: ModuleId,
    pub payload: ImplementationResponse,
}

/// Provider observation. Sequence numbers are host-checked for monotonicity by the process owner;
/// this message only establishes the closed wire shape and module schema identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationObservationEnvelope {
    pub protocol: String,
    pub implementation_id: String,
    pub module: ModuleId,
    pub run_id: String,
    pub sequence: u32,
    pub schema: ContractRef,
    pub terminal: bool,
    pub observation: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImplementationProtocolError {
    #[error("implementation protocol message is {actual} bytes; maximum is {max}")]
    TooLarge { actual: usize, max: usize },
    #[error("implementation protocol message is invalid JSON: {0}")]
    MalformedJson(String),
    #[error("implementation protocol identity or correlation is invalid")]
    Correlation,
    #[error("implementation protocol contract does not match the declared module seam")]
    Contract,
    #[error("implementation protocol field is invalid: {0}")]
    Field(&'static str),
    #[error("implementation response does not match its request operation")]
    Operation,
}

pub fn parse_implementation_request(
    bytes: &[u8],
) -> Result<ImplementationRequestEnvelope, ImplementationProtocolError> {
    let request: ImplementationRequestEnvelope = parse(bytes)?;
    request.validate()?;
    Ok(request)
}

pub fn parse_implementation_response(
    bytes: &[u8],
) -> Result<ImplementationResponseEnvelope, ImplementationProtocolError> {
    parse(bytes)
}

pub fn parse_implementation_response_for(
    bytes: &[u8],
    request: &ImplementationRequestEnvelope,
) -> Result<ImplementationResponseEnvelope, ImplementationProtocolError> {
    let response: ImplementationResponseEnvelope = parse(bytes)?;
    response.validate_for(request)?;
    Ok(response)
}

pub fn parse_implementation_observation(
    bytes: &[u8],
) -> Result<ImplementationObservationEnvelope, ImplementationProtocolError> {
    let observation: ImplementationObservationEnvelope = parse(bytes)?;
    observation.validate()?;
    Ok(observation)
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ImplementationProtocolError> {
    if bytes.len() > MAX_IMPLEMENTATION_MESSAGE_BYTES {
        return Err(ImplementationProtocolError::TooLarge {
            actual: bytes.len(),
            max: MAX_IMPLEMENTATION_MESSAGE_BYTES,
        });
    }
    serde_json::from_slice(bytes)
        .map_err(|error| ImplementationProtocolError::MalformedJson(error.to_string()))
}

impl ImplementationRequestEnvelope {
    pub fn validate(&self) -> Result<(), ImplementationProtocolError> {
        validate_envelope_identity(&self.protocol, &self.request_id, &self.implementation_id)?;
        let node = seam(self.module)?;
        match &self.payload {
            ImplementationRequest::Load {
                lifecycle_contract,
                definition_contract,
                provider_contract,
                consumer_contract,
                observation_schema,
                artifact_sha256,
                ..
            } => {
                if lifecycle_contract != &node.lifecycle.load
                    || definition_contract != &node.definition_contract
                    || provider_contract != &node.provider_contract
                    || consumer_contract != &node.consumer_contract
                    || observation_schema != &node.observation_schema
                    || !valid_digest(artifact_sha256)
                {
                    return Err(ImplementationProtocolError::Contract);
                }
            }
            ImplementationRequest::Start {
                lifecycle_contract,
                run_id,
                candidate_sha256,
                input_schema,
                input,
                deadline_ms,
            } => {
                if lifecycle_contract != &node.lifecycle.start
                    || input_schema != &node.consumer_contract
                {
                    return Err(ImplementationProtocolError::Contract);
                }
                if !valid_id(run_id) || !valid_digest(candidate_sha256) || *deadline_ms == 0 {
                    return Err(ImplementationProtocolError::Field("start"));
                }
                bounded_payload(input)?;
            }
            ImplementationRequest::Cancel {
                lifecycle_contract,
                run_id,
                reason,
            } => {
                if lifecycle_contract != &node.lifecycle.cancel {
                    return Err(ImplementationProtocolError::Contract);
                }
                validate_run_reason(run_id, reason)?;
            }
            ImplementationRequest::Stop {
                lifecycle_contract,
                reason,
            } => {
                if lifecycle_contract != &node.lifecycle.stop {
                    return Err(ImplementationProtocolError::Contract);
                }
                validate_text(reason, MAX_FAILURE_MESSAGE_BYTES, "stop.reason")?;
            }
        }
        Ok(())
    }
}

impl ImplementationResponseEnvelope {
    pub fn validate_for(
        &self,
        request: &ImplementationRequestEnvelope,
    ) -> Result<(), ImplementationProtocolError> {
        request.validate()?;
        validate_envelope_identity(&self.protocol, &self.request_id, &self.implementation_id)?;
        if self.request_id != request.request_id
            || self.implementation_id != request.implementation_id
            || self.module != request.module
        {
            return Err(ImplementationProtocolError::Correlation);
        }
        let node = seam(self.module)?;
        let matches = match (&request.payload, &self.payload) {
            (
                ImplementationRequest::Load { .. },
                ImplementationResponse::Loaded {
                    provider_contract,
                    observation_schema,
                },
            ) => {
                provider_contract == &node.provider_contract
                    && observation_schema == &node.observation_schema
            }
            (
                ImplementationRequest::Start { run_id, .. },
                ImplementationResponse::Started {
                    run_id: response_id,
                },
            )
            | (
                ImplementationRequest::Cancel { run_id, .. },
                ImplementationResponse::Cancelled {
                    run_id: response_id,
                },
            ) => run_id == response_id,
            (ImplementationRequest::Stop { .. }, ImplementationResponse::Stopped) => true,
            (_, ImplementationResponse::Failed { code, message }) => {
                validate_text(code, MAX_PROTOCOL_ID_BYTES, "failure.code")?;
                validate_text(message, MAX_FAILURE_MESSAGE_BYTES, "failure.message")?;
                true
            }
            _ => false,
        };
        if !matches {
            return Err(ImplementationProtocolError::Operation);
        }
        Ok(())
    }
}

impl ImplementationObservationEnvelope {
    pub fn validate(&self) -> Result<(), ImplementationProtocolError> {
        if self.protocol != IMPLEMENTATION_PROTOCOL
            || !valid_id(&self.implementation_id)
            || !valid_id(&self.run_id)
        {
            return Err(ImplementationProtocolError::Correlation);
        }
        let node = seam(self.module)?;
        if self.schema != node.observation_schema {
            return Err(ImplementationProtocolError::Contract);
        }
        bounded_payload(&self.observation)
    }
}

fn seam(
    module: ModuleId,
) -> Result<iteron_tunables::CapabilitySeamNode, ImplementationProtocolError> {
    let graph = capability_seam_graph();
    validate_capability_seam_graph(&graph).map_err(|_| ImplementationProtocolError::Contract)?;
    graph
        .nodes
        .into_iter()
        .find(|node| node.module == module)
        .ok_or(ImplementationProtocolError::Contract)
}

fn validate_envelope_identity(
    protocol: &str,
    request_id: &str,
    implementation_id: &str,
) -> Result<(), ImplementationProtocolError> {
    if protocol != IMPLEMENTATION_PROTOCOL || !valid_id(request_id) || !valid_id(implementation_id)
    {
        return Err(ImplementationProtocolError::Correlation);
    }
    Ok(())
}

fn validate_run_reason(run_id: &str, reason: &str) -> Result<(), ImplementationProtocolError> {
    if !valid_id(run_id) {
        return Err(ImplementationProtocolError::Field("run_id"));
    }
    validate_text(reason, MAX_FAILURE_MESSAGE_BYTES, "reason")
}

fn validate_text(
    value: &str,
    max: usize,
    field: &'static str,
) -> Result<(), ImplementationProtocolError> {
    if value.is_empty()
        || value.len() > max
        || value
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r'))
    {
        return Err(ImplementationProtocolError::Field(field));
    }
    Ok(())
}

fn bounded_payload(value: &serde_json::Value) -> Result<(), ImplementationProtocolError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ImplementationProtocolError::MalformedJson(error.to_string()))?;
    if bytes.len() > MAX_IMPLEMENTATION_PAYLOAD_BYTES {
        return Err(ImplementationProtocolError::TooLarge {
            actual: bytes.len(),
            max: MAX_IMPLEMENTATION_PAYLOAD_BYTES,
        });
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROTOCOL_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@' | b'+')
        })
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
