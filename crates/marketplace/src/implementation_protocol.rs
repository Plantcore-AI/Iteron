//! Language-neutral process protocol for replaceable optimization implementations.
//!
//! The marketplace admits bytes and prepares a process launch; this module defines the bounded
//! JSON messages exchanged after launch. The provider may return decisions and observations, but
//! it never receives activation, promotion, permission, budget, or evidence authority.

use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::{
    ContractRef, ModuleId, capability_seam_graph, validate_capability_seam_graph,
};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::BTreeSet;
use std::fmt;

pub const IMPLEMENTATION_PROTOCOL_V1: &str = "iteron-implementation/1";
pub const IMPLEMENTATION_PROTOCOL: &str = "iteron-implementation/2";
pub const MAX_IMPLEMENTATION_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_IMPLEMENTATION_PAYLOAD_BYTES: usize = 512 * 1024;
pub const MAX_IMPLEMENTATION_STATE_BYTES: usize = 512 * 1024;
pub const MAX_IMPLEMENTATION_STATE_DEADLINE_MS: u64 = 3_600_000;
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
    Snapshot {
        lifecycle_contract: ContractRef,
        run_id: String,
        generation: u64,
        state_schema: ContractRef,
        deadline_ms: u64,
    },
    Restore {
        lifecycle_contract: ContractRef,
        state: ImplementationState,
        deadline_ms: u64,
    },
    Migrate {
        lifecycle_contract: ContractRef,
        source: ImplementationState,
        target_generation: u64,
        deadline_ms: u64,
    },
    Readiness {
        lifecycle_contract: ContractRef,
        run_id: String,
        generation: u64,
        state_schema: ContractRef,
        state_sha256: String,
        deadline_ms: u64,
    },
}

/// Bounded, content-addressed provider state with an explicit source/target identity binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationState {
    pub module: ModuleId,
    pub implementation_id: String,
    pub run_id: String,
    pub generation: u64,
    pub state_schema: ContractRef,
    pub state_sha256: String,
    pub state: serde_json::Value,
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
    Snapshotted {
        state: ImplementationState,
    },
    Restored {
        run_id: String,
        generation: u64,
        state_schema: ContractRef,
        state_sha256: String,
    },
    Migrated {
        state: ImplementationState,
    },
    Ready {
        run_id: String,
        generation: u64,
        state_schema: ContractRef,
        state_sha256: String,
    },
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
    #[error("implementation protocol JSON contains a duplicate object key")]
    DuplicateJsonKey,
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
    serde_json::from_value(strict_json_value(bytes)?)
        .map_err(|error| ImplementationProtocolError::MalformedJson(error.to_string()))
}

pub(crate) fn strict_json_value(
    bytes: &[u8],
) -> Result<serde_json::Value, ImplementationProtocolError> {
    use serde::de::DeserializeSeed as _;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictSeed
        .deserialize(&mut deserializer)
        .map_err(classify_json)?;
    deserializer.end().map_err(classify_json)?;
    Ok(value)
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
            ImplementationRequest::Snapshot {
                lifecycle_contract,
                run_id,
                generation,
                state_schema,
                deadline_ms,
            } => {
                require_v2(&self.protocol)?;
                if lifecycle_contract != &node.lifecycle.snapshot
                    || state_schema != &node.lifecycle.snapshot
                {
                    return Err(ImplementationProtocolError::Contract);
                }
                validate_state_identity(run_id, *generation, *deadline_ms)?;
            }
            ImplementationRequest::Restore {
                lifecycle_contract,
                state,
                deadline_ms,
            } => {
                require_v2(&self.protocol)?;
                if lifecycle_contract != &node.lifecycle.restore {
                    return Err(ImplementationProtocolError::Contract);
                }
                validate_state_deadline(*deadline_ms)?;
                state.validate()?;
                if state.module != self.module || state.implementation_id != self.implementation_id
                {
                    return Err(ImplementationProtocolError::Correlation);
                }
            }
            ImplementationRequest::Migrate {
                lifecycle_contract,
                source,
                target_generation,
                deadline_ms,
            } => {
                require_v2(&self.protocol)?;
                if lifecycle_contract != &node.lifecycle.migrate {
                    return Err(ImplementationProtocolError::Contract);
                }
                validate_state_deadline(*deadline_ms)?;
                source.validate()?;
                if source.module != self.module {
                    return Err(ImplementationProtocolError::Correlation);
                }
                if *target_generation <= source.generation {
                    return Err(ImplementationProtocolError::Field("target_generation"));
                }
            }
            ImplementationRequest::Readiness {
                lifecycle_contract,
                run_id,
                generation,
                state_schema,
                state_sha256,
                deadline_ms,
            } => {
                require_v2(&self.protocol)?;
                if lifecycle_contract != &node.lifecycle.readiness
                    || state_schema != &node.lifecycle.snapshot
                {
                    return Err(ImplementationProtocolError::Contract);
                }
                validate_state_identity(run_id, *generation, *deadline_ms)?;
                if !valid_digest(state_sha256) {
                    return Err(ImplementationProtocolError::Field("state_sha256"));
                }
            }
        }
        Ok(())
    }
}

impl ImplementationState {
    pub fn new(
        module: ModuleId,
        implementation_id: impl Into<String>,
        run_id: impl Into<String>,
        generation: u64,
        state_schema: ContractRef,
        state: serde_json::Value,
    ) -> Result<Self, ImplementationProtocolError> {
        bounded_state(&state)?;
        let state_sha256 = state_digest(&state)?;
        Ok(Self {
            module,
            implementation_id: implementation_id.into(),
            run_id: run_id.into(),
            generation,
            state_schema,
            state_sha256,
            state,
        })
    }

    pub fn validate(&self) -> Result<(), ImplementationProtocolError> {
        let node = seam(self.module)?;
        if !valid_id(&self.implementation_id) || !valid_id(&self.run_id) || self.generation == 0 {
            return Err(ImplementationProtocolError::Field("state.identity"));
        }
        if self.state_schema != node.lifecycle.snapshot {
            return Err(ImplementationProtocolError::Contract);
        }
        bounded_state(&self.state)?;
        if !valid_digest(&self.state_sha256) || state_digest(&self.state)? != self.state_sha256 {
            return Err(ImplementationProtocolError::Field("state_sha256"));
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
            || self.protocol != request.protocol
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
            (
                ImplementationRequest::Snapshot {
                    run_id,
                    generation,
                    state_schema,
                    ..
                },
                ImplementationResponse::Snapshotted { state },
            ) => {
                state.validate()?;
                state.run_id == *run_id
                    && state.generation == *generation
                    && state.state_schema == *state_schema
                    && state.module == self.module
                    && state.implementation_id == self.implementation_id
            }
            (
                ImplementationRequest::Restore { state, .. },
                ImplementationResponse::Restored {
                    run_id,
                    generation,
                    state_schema,
                    state_sha256,
                },
            ) => {
                state.run_id == *run_id
                    && state.generation == *generation
                    && state.state_schema == *state_schema
                    && state.state_sha256 == *state_sha256
            }
            (
                ImplementationRequest::Migrate {
                    source,
                    target_generation,
                    ..
                },
                ImplementationResponse::Migrated { state },
            ) => {
                state.validate()?;
                state.run_id == source.run_id
                    && state.generation == *target_generation
                    && state.state_schema == source.state_schema
                    && state.module == self.module
                    && state.implementation_id == self.implementation_id
            }
            (
                ImplementationRequest::Readiness {
                    run_id,
                    generation,
                    state_schema,
                    state_sha256,
                    ..
                },
                ImplementationResponse::Ready {
                    run_id: response_run,
                    generation: response_generation,
                    state_schema: response_schema,
                    state_sha256: response_digest,
                },
            ) => {
                run_id == response_run
                    && generation == response_generation
                    && state_schema == response_schema
                    && state_sha256 == response_digest
            }
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
        if !supported_protocol(&self.protocol)
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
    if !supported_protocol(protocol) || !valid_id(request_id) || !valid_id(implementation_id) {
        return Err(ImplementationProtocolError::Correlation);
    }
    Ok(())
}

fn supported_protocol(protocol: &str) -> bool {
    matches!(
        protocol,
        IMPLEMENTATION_PROTOCOL_V1 | IMPLEMENTATION_PROTOCOL
    )
}

fn require_v2(protocol: &str) -> Result<(), ImplementationProtocolError> {
    if protocol == IMPLEMENTATION_PROTOCOL {
        Ok(())
    } else {
        Err(ImplementationProtocolError::Operation)
    }
}

fn validate_state_identity(
    run_id: &str,
    generation: u64,
    deadline_ms: u64,
) -> Result<(), ImplementationProtocolError> {
    if !valid_id(run_id) || generation == 0 {
        return Err(ImplementationProtocolError::Field("state.identity"));
    }
    validate_state_deadline(deadline_ms)
}

fn validate_state_deadline(deadline_ms: u64) -> Result<(), ImplementationProtocolError> {
    if deadline_ms == 0 || deadline_ms > MAX_IMPLEMENTATION_STATE_DEADLINE_MS {
        Err(ImplementationProtocolError::Field("state.deadline_ms"))
    } else {
        Ok(())
    }
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

fn bounded_state(value: &serde_json::Value) -> Result<(), ImplementationProtocolError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ImplementationProtocolError::MalformedJson(error.to_string()))?;
    if bytes.len() > MAX_IMPLEMENTATION_STATE_BYTES {
        return Err(ImplementationProtocolError::TooLarge {
            actual: bytes.len(),
            max: MAX_IMPLEMENTATION_STATE_BYTES,
        });
    }
    Ok(())
}

pub fn implementation_state_sha256(
    value: &serde_json::Value,
) -> Result<String, ImplementationProtocolError> {
    bounded_state(value)?;
    state_digest(value)
}

fn state_digest(value: &serde_json::Value) -> Result<String, ImplementationProtocolError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ImplementationProtocolError::MalformedJson(error.to_string()))?;
    Ok(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(bytes))
    ))
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

const DUPLICATE_KEY_MARKER: &str = "__iteron_duplicate_json_key__";

#[derive(Clone, Copy)]
struct StrictSeed;

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a duplicate-free JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(value.to_owned().into())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(DUPLICATE_KEY_MARKER));
            }
            values.insert(key, map.next_value_seed(StrictSeed)?);
        }
        Ok(serde_json::Value::Object(values))
    }
}

fn classify_json(error: serde_json::Error) -> ImplementationProtocolError {
    if error.to_string().contains(DUPLICATE_KEY_MARKER) {
        ImplementationProtocolError::DuplicateJsonKey
    } else {
        ImplementationProtocolError::MalformedJson(error.to_string())
    }
}
