//! Offline, typed machine capability document and portable canonical JSON implementation.

use serde::{Serialize, de};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MACHINE_CONTRACT_SCHEMA_VERSION: u32 = 3;
const MACHINE_CONTRACT_TYPE: &str = "machine_contract";
const MACHINE_CONTRACT_VERSION: &str = "plantcore.iteron.machine-contract.v1";
const PORTABLE_CANONICAL_JSON_VERSION: &str = "plantcore.portable-canonical-json.v1";
const PORTABLE_CANONICAL_JSON_ALGORITHM: &str = "utf8-sorted-compact-integer-only-v1";
const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
const MAX_CANONICAL_DEPTH: usize = 32;
const MAX_PROBE_BYTES: u64 = 1_048_576;
const V7_SCHEMA_ID: &str = "plantcore.iteron-output.v7.target";
const V7_SCHEMA_CANONICAL_SHA256: &str =
    "83ef558efc9c72b375d9f981a73285831b1936ae1e547cef0a67d9ce1d6c30bc";
const V7_SCHEMA_BYTES: &[u8] =
    include_bytes!("../../../contracts/plantcore/iteron-output-v7.schema.json");

#[derive(Debug, Serialize)]
pub(crate) struct MachineContract {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    contract_version: &'static str,
    release_id: String,
    cli_stream_versions: Vec<u32>,
    default_cli_stream_version: u32,
    resident_protocol_version: u32,
    canonical_json: CanonicalJsonCapability,
    plantcore_capabilities: PlantcoreCapabilities,
    limits: MachineContractLimits,
    contract_artifacts: ContractArtifacts,
}

#[derive(Debug, Serialize)]
struct CanonicalJsonCapability {
    version: &'static str,
    algorithm: &'static str,
    maximum_depth: usize,
    maximum_safe_integer: u64,
    rejects_duplicate_keys: bool,
}

#[derive(Debug, Serialize)]
struct MachineContractLimits {
    machine_contract_max_bytes: u64,
    logical_v7_event_max_bytes: u64,
}

#[derive(Debug, Serialize)]
struct ContractArtifacts {
    machine_contract_schema: ContractArtifact,
    app_server_v4_schema: ContractArtifact,
    output_v7_target_schema: ContractArtifact,
    workspace_hook_v1_schema: ContractArtifact,
}

#[derive(Debug, Serialize)]
struct ContractArtifact {
    id: &'static str,
    path: &'static str,
    canonical_sha256: String,
}

#[derive(Debug, Serialize)]
struct PlantcoreCapabilities {
    supported_operating_systems: Vec<&'static str>,
    resident_bootstrap: &'static str,
    resident_server: ResidentServerCapabilities,
    input: Vec<&'static str>,
    input_operations: Vec<&'static str>,
    immutable_agent_instructions: bool,
    controls: ControlCapabilities,
    external_mcp_postures: Vec<&'static str>,
    external_mcp_transport: &'static str,
    budget_limits: Vec<&'static str>,
    usage: UsageCapabilities,
    typed_usage_per_dispatched_logical_turn: bool,
    usage_unavailable: bool,
    typed_product_result: bool,
    product_result_statuses: Vec<&'static str>,
    product_tools: Vec<&'static str>,
    workspace: WorkspaceCapabilities,
    consecutive_tool_error_threshold: u32,
}

#[derive(Debug, Serialize)]
struct ResidentServerCapabilities {
    command: &'static str,
    transport: &'static str,
    listen: &'static str,
}

#[derive(Debug, Serialize)]
struct ControlCapabilities {
    resume_same_process: bool,
    command_idempotency: &'static str,
    commands: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct UsageCapabilities {
    statuses: Vec<&'static str>,
    calculator_contract_version: &'static str,
    unit: &'static str,
    counters: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct WorkspaceCapabilities {
    postures: Vec<&'static str>,
    pre_tool_use_hook_contract: &'static str,
    hook_timeout_milliseconds: u64,
    protection_scope: &'static str,
}

impl MachineContract {
    fn current() -> Result<Self, CanonicalJsonError> {
        let canonical_v7_schema = canonicalize_json(V7_SCHEMA_BYTES)?;
        let actual_schema_digest = lower_sha256(&canonical_v7_schema);
        if actual_schema_digest != V7_SCHEMA_CANONICAL_SHA256 {
            return Err(CanonicalJsonError::new(
                "embedded PlantCore v7 target schema digest does not match the reviewed authority",
            ));
        }

        Ok(Self {
            schema_version: MACHINE_CONTRACT_SCHEMA_VERSION,
            kind: MACHINE_CONTRACT_TYPE,
            contract_version: MACHINE_CONTRACT_VERSION,
            release_id: format!("iteron-v{}", env!("CARGO_PKG_VERSION")),
            cli_stream_versions: crate::output::SUPPORTED_SCHEMA_VERSIONS.to_vec(),
            default_cli_stream_version: crate::output::DEFAULT_SCHEMA_VERSION,
            resident_protocol_version: iteron_protocol::PROTOCOL_VERSION,
            canonical_json: CanonicalJsonCapability {
                version: PORTABLE_CANONICAL_JSON_VERSION,
                algorithm: PORTABLE_CANONICAL_JSON_ALGORITHM,
                maximum_depth: MAX_CANONICAL_DEPTH,
                maximum_safe_integer: MAX_SAFE_INTEGER,
                rejects_duplicate_keys: true,
            },
            plantcore_capabilities: PlantcoreCapabilities {
                supported_operating_systems: vec!["linux"],
                resident_bootstrap: "plantcore.iteron-run-bootstrap.v1",
                resident_server: ResidentServerCapabilities {
                    command: "serve",
                    transport: "loopback_tcp_jsonl",
                    listen: "127.0.0.1:0",
                },
                input: vec!["text", "image", "file"],
                input_operations: vec!["user_input", "user_input_v2", "user_input_v3"],
                immutable_agent_instructions: true,
                controls: ControlCapabilities {
                    resume_same_process: true,
                    command_idempotency: "plantcore_command_v1",
                    commands: vec![
                        "steer",
                        "interrupt",
                        "drain",
                        "pause_dispatch_after_safe_point",
                        "resume_dispatch",
                    ],
                },
                external_mcp_postures: vec!["disabled", "run_gateway"],
                external_mcp_transport: "streamable_http",
                budget_limits: vec!["max_turns", "max_tokens", "max_usd", "max_wall_secs"],
                usage: UsageCapabilities {
                    statuses: vec!["complete", "unavailable"],
                    calculator_contract_version: "plantcore.metering.five-class-ceil.v1",
                    unit: "USD_MICRO",
                    counters: vec![
                        "input_tokens",
                        "output_tokens",
                        "cache_creation_tokens",
                        "cache_read_tokens",
                        "thinking_tokens",
                    ],
                },
                typed_usage_per_dispatched_logical_turn: true,
                usage_unavailable: true,
                typed_product_result: true,
                product_result_statuses: vec!["completed", "needs_input"],
                product_tools: vec!["request_user_input", "publish_artifact"],
                workspace: WorkspaceCapabilities {
                    postures: vec!["read_only", "read_write"],
                    pre_tool_use_hook_contract: "plantcore.iteron.workspace-hook.v1",
                    hook_timeout_milliseconds: 2_000,
                    protection_scope: "model_visible_tool_paths_only",
                },
                consecutive_tool_error_threshold: 5,
            },
            limits: MachineContractLimits {
                machine_contract_max_bytes: MAX_PROBE_BYTES,
                logical_v7_event_max_bytes: 65_536,
            },
            contract_artifacts: ContractArtifacts {
                machine_contract_schema: ContractArtifact {
                    id: MACHINE_CONTRACT_VERSION,
                    path: "contracts/plantcore/machine-contract.schema.json",
                    canonical_sha256: lower_sha256(&canonicalize_json(include_bytes!(
                        "../../../contracts/plantcore/machine-contract.schema.json"
                    ))?),
                },
                app_server_v4_schema: ContractArtifact {
                    id: "plantcore.iteron.app-server.v4",
                    path: "contracts/plantcore/app-server-v4.schema.json",
                    canonical_sha256: lower_sha256(&canonicalize_json(include_bytes!(
                        "../../../contracts/plantcore/app-server-v4.schema.json"
                    ))?),
                },
                output_v7_target_schema: ContractArtifact {
                    id: V7_SCHEMA_ID,
                    path: "contracts/plantcore/iteron-output-v7.schema.json",
                    canonical_sha256: actual_schema_digest,
                },
                workspace_hook_v1_schema: ContractArtifact {
                    id: "plantcore.iteron.workspace-hook.v1",
                    path: "contracts/plantcore/workspace-hook-v1.schema.json",
                    canonical_sha256: lower_sha256(&canonicalize_json(include_bytes!(
                        "../../../contracts/plantcore/workspace-hook-v1.schema.json"
                    ))?),
                },
            },
        })
    }
}

pub(crate) fn render() -> anyhow::Result<String> {
    // Pretty output is retained for the dependency-free release installer. Consumers compute the
    // admitted digest from parsed portable-canonical bytes, never from this presentation.
    let rendered = serde_json::to_string_pretty(&MachineContract::current()?)?;
    if rendered.len() + 1 > MAX_PROBE_BYTES as usize {
        anyhow::bail!("machine contract exceeds the 1 MiB probe limit");
    }
    Ok(rendered)
}

pub(crate) fn lower_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalJsonError {
    message: String,
}

impl CanonicalJsonError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CanonicalJsonError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CanonicalJsonError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CanonicalValue {
    Null,
    Bool(bool),
    Integer(i64),
    UnsignedInteger(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl Serialize for CanonicalValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Integer(value) => serializer.serialize_i64(*value),
            Self::UnsignedInteger(value) => serializer.serialize_u64(*value),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(values) => values.serialize(serializer),
            Self::Object(values) => values.serialize(serializer),
        }
    }
}

struct CanonicalValueSeed {
    depth: usize,
}

impl<'de> de::DeserializeSeed<'de> for CanonicalValueSeed {
    type Value = CanonicalValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_CANONICAL_DEPTH {
            return Err(de::Error::custom(
                "portable canonical JSON exceeds depth 32",
            ));
        }
        deserializer.deserialize_any(CanonicalValueVisitor { depth: self.depth })
    }
}

struct CanonicalValueVisitor {
    depth: usize,
}

impl<'de> de::Visitor<'de> for CanonicalValueVisitor {
    type Value = CanonicalValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("portable canonical JSON")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom(
                "portable canonical JSON integer exceeds the ±(2^53−1) range",
            ));
        }
        Ok(CanonicalValue::Integer(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value > MAX_SAFE_INTEGER {
            return Err(E::custom(
                "portable canonical JSON integer exceeds the ±(2^53−1) range",
            ));
        }
        Ok(CanonicalValue::UnsignedInteger(value))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(
            "portable canonical JSON does not accept floating-point numbers",
        ))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(CanonicalValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(CanonicalValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(CanonicalValueSeed {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(CanonicalValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "portable canonical JSON rejects duplicate object key {key:?}"
                )));
            }
            let value = map.next_value_seed(CanonicalValueSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(CanonicalValue::Object(values))
    }
}

pub(crate) fn canonicalize_json(input: &[u8]) -> Result<Vec<u8>, CanonicalJsonError> {
    use serde::de::DeserializeSeed as _;

    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = CanonicalValueSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| CanonicalJsonError::new(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| CanonicalJsonError::new(error.to_string()))?;
    serde_json::to_vec(&value).map_err(|error| CanonicalJsonError::new(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTOR: &[u8] =
        include_bytes!("../../../contracts/plantcore/test-vectors/portable-canonical-json-v1.json");

    #[test]
    fn platform_portable_canonical_json_vector_matches_exact_bytes_and_digest() {
        let vector: Value = serde_json::from_slice(VECTOR).expect("reviewed Platform vector");
        let payload = serde_json::to_vec(&vector["payload"]).expect("vector payload");
        let canonical = canonicalize_json(&payload).expect("portable payload");
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            vector["canonical_json"].as_str().unwrap()
        );
        assert_eq!(hex::encode(&canonical), vector["canonical_hex"]);
        assert_eq!(lower_sha256(&canonical), vector["sha256"]);
    }

    #[test]
    fn portable_canonical_json_rejects_every_platform_negative_class() {
        assert!(canonicalize_json(br#"{"value":1.5}"#).is_err());
        assert!(canonicalize_json(br#"{"value":9007199254740992}"#).is_err());
        assert!(canonicalize_json(br#"{"value":"\ud800"}"#).is_err());
        assert!(canonicalize_json(br#"{"duplicate":1,"duplicate":2}"#).is_err());

        let mut deep = "null".to_owned();
        for _ in 0..34 {
            deep = format!("[{deep}]");
        }
        assert!(canonicalize_json(deep.as_bytes()).is_err());
    }

    #[test]
    fn machine_contract_is_bounded_typed_and_truthful_about_current_output_support() {
        let rendered = render().expect("render offline contract");
        assert!(rendered.len() < MAX_PROBE_BYTES as usize);
        let value: Value = serde_json::from_str(&rendered).expect("machine contract JSON");
        assert_eq!(value["schema_version"], 3);
        assert_eq!(value["type"], "machine_contract");
        assert_eq!(value["cli_stream_versions"], serde_json::json!([4, 5, 6]));
        assert_eq!(value["default_cli_stream_version"], 6);
        assert_eq!(
            value["contract_artifacts"]["output_v7_target_schema"]["canonical_sha256"],
            V7_SCHEMA_CANONICAL_SHA256
        );
        assert_eq!(
            value["plantcore_capabilities"]["consecutive_tool_error_threshold"],
            5
        );
    }

    #[test]
    fn parsed_machine_contract_digest_is_distinct_from_raw_sidecar_digest() {
        let pretty = render().expect("render offline contract");
        let canonical = canonicalize_json(pretty.as_bytes()).expect("canonical machine contract");
        assert_ne!(lower_sha256(pretty.as_bytes()), lower_sha256(&canonical));
        assert_eq!(
            canonical,
            canonicalize_json(&canonical).expect("canonicalization is idempotent")
        );
    }
}
