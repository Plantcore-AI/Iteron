//! Typed facts shared by the PlantCore resident admission, runtime accounting, and v7 projector.
//!
//! These types deliberately contain no Worker/Control identifiers such as `lease_fence`,
//! `engine_seq`, `event_id`, or Gateway artifact ids. The resident bridge receives immutable Run
//! facts; the Worker adds cross-process delivery identities after receiving canonical engine bytes.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

use crate::Outcome;

pub const RUN_BOOTSTRAP_CONTRACT_VERSION: &str = "plantcore.iteron-run-bootstrap.v1";
pub const FIVE_CLASS_CALCULATOR_VERSION: &str = "plantcore.metering.five-class-ceil.v1";
pub const NATIVE_METERING_UNIT: &str = "USD_MICRO";
pub const MAX_ARTIFACTS: usize = 50;
pub const MAX_ARTIFACT_BYTES: u64 = 100 * 1024 * 1024;
pub const MAX_TOTAL_ARTIFACT_BYTES: u64 = 500 * 1024 * 1024;
pub const MAX_UPLOAD_CHUNK_BYTES: u32 = 8 * 1024 * 1024;
pub const MAX_ASSISTANT_TEXT_BYTES: usize = 65_536;
pub const MAX_QUESTION_PROMPT_BYTES: usize = 65_536;

/// A JSON bootstrap digest: exactly 32 bytes rendered as 64 lowercase hexadecimal characters.
///
/// The v7 public projection adds its required `sha256:` prefix at the output seam. Keeping this
/// type prefix-free prevents the same bytes from being confused with the public JSON spelling.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexSha256([u8; 32]);

impl HexSha256 {
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn to_lower_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut rendered = String::with_capacity(64);
        for byte in self.0 {
            rendered.push(char::from(HEX[usize::from(byte >> 4)]));
            rendered.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        rendered
    }
}

impl fmt::Debug for HexSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_lower_hex())
    }
}

impl fmt::Display for HexSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_lower_hex())
    }
}

impl FromStr for HexSha256 {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err("sha256 digest must contain exactly 64 lowercase hexadecimal characters");
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = decode_lower_hex(pair[0])?;
            let low = decode_lower_hex(pair[1])?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

fn decode_lower_hex(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("sha256 digest must use lowercase hexadecimal characters"),
    }
}

impl Serialize for HexSha256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_lower_hex())
    }
}

impl<'de> Deserialize<'de> for HexSha256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineEffort {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
    Ultracode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinWorkspacePosture {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalMcpPosture {
    Disabled,
    RunGateway,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeProfile {
    pub agent_definition_id: String,
    pub agent_definition_version: String,
    pub instructions_utf8: String,
    pub instructions_sha256: HexSha256,
    pub capability_policy_digest_sha256: HexSha256,
    pub profile_digest_sha256: HexSha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlantcoreEngineSpec {
    pub provider: String,
    pub model: String,
    pub effort: EngineEffort,
    pub allow_code: bool,
    pub builtin_workspace_posture: BuiltinWorkspacePosture,
    pub external_mcp_posture: ExternalMcpPosture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBootstrap {
    pub api_origin: String,
    pub policy_version: String,
    pub policy_digest_sha256: HexSha256,
    pub credential_env_name: String,
    pub credential_projected_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGatewayBootstrap {
    pub mcp_url: String,
    pub run_io_base_url: String,
    pub auth_header_name: String,
    pub token_env_name: String,
    pub mcp_config_version: String,
    pub mcp_config_digest_sha256: HexSha256,
    pub catalog_snapshot_digest_sha256: HexSha256,
    pub catalog_snapshot_revision: String,
    pub external_mcp_posture: ExternalMcpPosture,
    pub run_io_token_projected_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveRunLimits {
    pub max_turns: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_usd_micros: Option<u64>,
    pub max_wall_secs: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering_policy_version: Option<String>,
    pub limits_digest_sha256: HexSha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiveClassCeilPolicyV1 {
    pub input_units_per_million: u64,
    pub output_units_per_million: u64,
    pub cache_creation_units_per_million: u64,
    pub cache_read_units_per_million: u64,
    pub thinking_units_per_million: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeteringPolicySnapshot {
    pub version: String,
    pub provider: String,
    pub model: String,
    pub effective_from_unix_ms: i64,
    pub effective_until_unix_ms: i64,
    pub calculator_contract_version: String,
    pub metering_unit: String,
    pub policy_digest_sha256: HexSha256,
    pub five_class_ceil_v1: FiveClassCeilPolicyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConversationFact {
    UserMessage {
        content_utf8: String,
        content_sha256: HexSha256,
        source_message_id: String,
    },
    AssistantMessage {
        content_utf8: String,
        content_sha256: HexSha256,
        source_message_id: String,
    },
    QuestionAnswer {
        question_id: String,
        question_digest_sha256: HexSha256,
        answer_utf8: String,
        answer_sha256: HexSha256,
        answered_by_actor_id: String,
        answered_at_unix_ms: i64,
    },
    ActionDecision {
        action_review_id: String,
        action_digest_sha256: HexSha256,
        decision: ActionDecision,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decided_by_actor_id: Option<String>,
        decided_at_unix_ms: i64,
    },
    ActionResult {
        action_review_id: String,
        action_digest_sha256: HexSha256,
        status: ActionEffectStatus,
        safe_summary_utf8: String,
        result_digest_sha256: HexSha256,
        connector_journal_id: String,
        completed_at_unix_ms: i64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionDecision {
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionEffectStatus {
    Succeeded,
    Failed,
    UnknownEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationSegment {
    pub sequence: u64,
    pub source_run_id: String,
    pub fact_digest_sha256: HexSha256,
    pub fact: ConversationFact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentUserInputSource {
    pub conversation_sequence: u64,
    pub source_run_id: String,
    pub source_message_id: String,
    pub content_sha256: HexSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputMaterialization {
    TextAttachment,
    ImageAttachment,
    WorkspaceReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputAssetRef {
    pub asset_handle: String,
    pub relative_path: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub content_sha256: HexSha256,
    pub materialization: InputMaterialization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRoots {
    pub input: String,
    pub work: String,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRequirement {
    pub logical_name: String,
    pub relative_path: String,
    pub allowed_media_types: Vec<String>,
    pub max_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPolicy {
    pub output_root: String,
    pub max_artifact_bytes: u64,
    pub max_artifact_count: u32,
    pub max_total_artifact_bytes: u64,
    pub max_upload_chunk_bytes: u32,
    pub required_artifacts: Vec<ArtifactRequirement>,
    pub policy_digest_sha256: HexSha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlantcoreRunBootstrapV1 {
    pub contract_version: String,
    pub run_id: String,
    pub agent_runtime_profile: AgentRuntimeProfile,
    pub engine: PlantcoreEngineSpec,
    pub provider_bootstrap: ProviderBootstrap,
    pub run_gateway: RunGatewayBootstrap,
    pub limits: EffectiveRunLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering_policy: Option<MeteringPolicySnapshot>,
    pub output_schema_version: u32,
    pub output_schema_digest_sha256: HexSha256,
    pub workspace: WorkspaceRoots,
    pub artifact_policy: ArtifactPolicy,
    pub conversation_segments: Vec<ConversationSegment>,
    pub current_user_input: CurrentUserInputSource,
    pub input_assets: Vec<InputAssetRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDeclaration {
    pub logical_name: String,
    pub relative_path: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub content_sha256: [u8; 32],
}

impl ArtifactDeclaration {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_nonempty_chars(&self.logical_name, 128, "artifact logical_name")?;
        validate_nonempty_chars(&self.relative_path, 512, "artifact relative_path")?;
        validate_nonempty_chars(&self.media_type, 128, "artifact media_type")?;
        if self.size_bytes > MAX_ARTIFACT_BYTES {
            return Err("artifact size_bytes exceeds 100 MiB");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub question_id: String,
    pub prompt_utf8: String,
    pub prompt_sha256: [u8; 32],
}

impl Question {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_nonempty_chars(&self.question_id, 128, "question_id")?;
        if self.prompt_utf8.is_empty() {
            return Err("question prompt_utf8 must not be empty");
        }
        if self.prompt_utf8.len() > MAX_QUESTION_PROMPT_BYTES {
            return Err("question prompt_utf8 exceeds 65,536 UTF-8 bytes");
        }
        if Sha256::digest(self.prompt_utf8.as_bytes()).as_slice() != self.prompt_sha256 {
            return Err("question prompt_sha256 does not match prompt_utf8");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductResult {
    Completed {
        assistant_text: String,
        artifacts: Vec<ArtifactDeclaration>,
    },
    NeedsInput {
        assistant_text: String,
        question: Question,
        artifacts: Vec<ArtifactDeclaration>,
    },
}

impl ProductResult {
    pub fn validate(&self) -> Result<(), &'static str> {
        let (assistant_text, artifacts) = match self {
            Self::Completed {
                assistant_text,
                artifacts,
            } => (assistant_text, artifacts),
            Self::NeedsInput {
                assistant_text,
                question,
                artifacts,
            } => {
                question.validate()?;
                if assistant_text.contains(&question.prompt_utf8) {
                    return Err("needs_input assistant text must not repeat the question prompt");
                }
                (assistant_text, artifacts)
            }
        };
        if assistant_text.len() > MAX_ASSISTANT_TEXT_BYTES {
            return Err("assistant text exceeds 65,536 UTF-8 bytes");
        }
        if artifacts.len() > MAX_ARTIFACTS {
            return Err("product result contains more than 50 artifacts");
        }
        for artifact in artifacts {
            artifact.validate()?;
        }
        Ok(())
    }
}

/// The closed terminal authority consumed by PlantCore schema-v7.
///
/// Unlike the generic kernel [`Outcome`], this type cannot represent `done` without a validated
/// product result or attach product data to a non-success terminal. The generic enum remains
/// unchanged so existing v4-v6 and record consumers keep their stable ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlantcoreTerminalOutcome {
    Done(ProductResult),
    Drained,
    BudgetExhausted(PlantcoreBudgetLimit),
    Interrupted,
    Stuck,
    HarnessError,
    UsageUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlantcoreBudgetLimit {
    MaxTurns,
    MaxTokens,
    MaxUsd,
    MaxWallSecs,
}

impl PlantcoreTerminalOutcome {
    pub fn from_runtime(
        outcome: Outcome,
        product_result: Option<ProductResult>,
    ) -> Result<Self, &'static str> {
        match outcome {
            Outcome::Done => {
                let product = product_result.ok_or("done outcome requires typed ProductResult")?;
                product.validate()?;
                Ok(Self::Done(product))
            }
            Outcome::Drained => reject_product(product_result, Self::Drained),
            Outcome::BudgetExhausted(limit) => reject_product(
                product_result,
                Self::BudgetExhausted(PlantcoreBudgetLimit::try_from(limit)?),
            ),
            Outcome::Interrupted => reject_product(product_result, Self::Interrupted),
            Outcome::Stuck => reject_product(product_result, Self::Stuck),
            Outcome::HarnessError => reject_product(product_result, Self::HarnessError),
            Outcome::UsageUnavailable => reject_product(product_result, Self::UsageUnavailable),
        }
    }

    #[must_use]
    pub fn outcome(&self) -> Outcome {
        match self {
            Self::Done(_) => Outcome::Done,
            Self::Drained => Outcome::Drained,
            Self::BudgetExhausted(limit) => Outcome::BudgetExhausted(limit.as_str()),
            Self::Interrupted => Outcome::Interrupted,
            Self::Stuck => Outcome::Stuck,
            Self::HarnessError => Outcome::HarnessError,
            Self::UsageUnavailable => Outcome::UsageUnavailable,
        }
    }
}

impl PlantcoreBudgetLimit {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxTurns => "max_turns",
            Self::MaxTokens => "max_tokens",
            Self::MaxUsd => "max_usd",
            Self::MaxWallSecs => "max_wall_secs",
        }
    }
}

impl TryFrom<&'static str> for PlantcoreBudgetLimit {
    type Error = &'static str;

    fn try_from(value: &'static str) -> Result<Self, Self::Error> {
        match value {
            "max_turns" => Ok(Self::MaxTurns),
            "max_tokens" => Ok(Self::MaxTokens),
            "max_usd" => Ok(Self::MaxUsd),
            "max_wall_secs" => Ok(Self::MaxWallSecs),
            _ => Err("v7 budget outcome has an unknown limit"),
        }
    }
}

fn reject_product(
    product_result: Option<ProductResult>,
    outcome: PlantcoreTerminalOutcome,
) -> Result<PlantcoreTerminalOutcome, &'static str> {
    if product_result.is_some() {
        return Err("non-done outcome cannot carry ProductResult");
    }
    Ok(outcome)
}

fn validate_nonempty_chars(
    value: &str,
    max_chars: usize,
    field: &'static str,
) -> Result<(), &'static str> {
    let count = value.chars().count();
    if count == 0 {
        return Err(match field {
            "artifact logical_name" => "artifact logical_name must not be empty",
            "artifact relative_path" => "artifact relative_path must not be empty",
            "artifact media_type" => "artifact media_type must not be empty",
            "question_id" => "question_id must not be empty",
            _ => "bounded string must not be empty",
        });
    }
    if count > max_chars {
        return Err(match field {
            "artifact logical_name" => "artifact logical_name exceeds 128 characters",
            "artifact relative_path" => "artifact relative_path exceeds 512 characters",
            "artifact media_type" => "artifact media_type exceeds 128 characters",
            "question_id" => "question_id exceeds 128 characters",
            _ => "bounded string exceeds its character limit",
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FiveClassUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub thinking_tokens: u64,
}

impl FiveClassUsage {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.thinking_tokens > self.output_tokens {
            return Err("thinking_tokens must not exceed output_tokens");
        }
        self.total_tokens()
            .ok_or("five-class token total exceeds u64")?;
        Ok(())
    }

    #[must_use]
    pub fn total_tokens(&self) -> Option<u64> {
        self.input_tokens
            .checked_add(self.output_tokens)?
            .checked_add(self.cache_creation_tokens)?
            .checked_add(self.cache_read_tokens)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metering {
    pub policy_version: String,
    pub policy_digest_sha256: [u8; 32],
    pub calculator_contract_version: String,
    pub cumulative_amount: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UsageUnavailableReason {
    ProviderOmitted,
    CacheCreationUnreported,
    ProvenFailureWithoutUsage,
    OutcomeUnobservable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnUsage {
    Complete {
        turn: u64,
        dispatched_attempt_count: u64,
        counters: FiveClassUsage,
        cumulative_metering: Option<Metering>,
    },
    Unavailable {
        turn: u64,
        dispatched_attempt_count: u64,
        reasons: Vec<UsageUnavailableReason>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_sha256_rejects_uppercase_and_wrong_length() {
        let digest = HexSha256::digest(b"plantcore");
        assert_eq!(digest.to_string().len(), 64);
        assert_eq!(digest.to_string().parse(), Ok(digest));
        assert!(
            "AA00000000000000000000000000000000000000000000000000000000000000"
                .parse::<HexSha256>()
                .is_err()
        );
        assert!("00".parse::<HexSha256>().is_err());
    }

    #[test]
    fn bootstrap_rejects_unknown_security_critical_fields() {
        let json = r#"{
            "contract_version":"plantcore.iteron-run-bootstrap.v1",
            "run_id":"run-1",
            "unknown_switch":true
        }"#;
        let error = serde_json::from_str::<PlantcoreRunBootstrapV1>(json).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn five_class_total_does_not_double_count_thinking() {
        let usage = FiveClassUsage {
            input_tokens: 10,
            output_tokens: 8,
            cache_creation_tokens: 3,
            cache_read_tokens: 2,
            thinking_tokens: 5,
        };
        assert_eq!(usage.total_tokens(), Some(23));
        assert_eq!(usage.validate(), Ok(()));
    }

    #[test]
    fn product_result_rejects_prompt_duplication_and_bad_artifact_limits() {
        let prompt = "which target?".to_owned();
        let question = Question {
            question_id: "iteron-question-test".to_owned(),
            prompt_sha256: Sha256::digest(prompt.as_bytes()).into(),
            prompt_utf8: prompt.clone(),
        };
        let result = ProductResult::NeedsInput {
            assistant_text: format!("Please answer: {prompt}"),
            question,
            artifacts: Vec::new(),
        };
        assert_eq!(
            result.validate(),
            Err("needs_input assistant text must not repeat the question prompt")
        );

        let artifact = ArtifactDeclaration {
            logical_name: "report".to_owned(),
            relative_path: "report.pdf".to_owned(),
            media_type: "application/pdf".to_owned(),
            size_bytes: MAX_ARTIFACT_BYTES + 1,
            content_sha256: [0; 32],
        };
        assert_eq!(
            artifact.validate(),
            Err("artifact size_bytes exceeds 100 MiB")
        );
    }
}
