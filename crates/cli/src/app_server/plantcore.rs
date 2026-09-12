use crate::machine_contract::{canonicalize_json, lower_sha256};
use crate::runtime::Agent;
use base64::Engine as _;
use iteron_protocol::input::{
    MAX_INPUT_FILES, MAX_INPUT_IMAGES, MAX_TOTAL_FILE_TEXT_BYTES, MAX_TOTAL_IMAGE_BASE64_BYTES,
};
use iteron_protocol::plantcore::{
    ActionDecision, ActionEffectStatus, BuiltinWorkspacePosture, ConversationFact, EngineEffort,
    ExternalMcpPosture, FIVE_CLASS_CALCULATOR_VERSION, HexSha256, InputAssetRef,
    InputMaterialization, NATIVE_METERING_UNIT, PlantcoreRunBootstrapV1,
    RUN_BOOTSTRAP_CONTRACT_VERSION,
};
use iteron_protocol::{
    Block, Capability, Effort, Message, Op, PermissionMode, PermissionRules, Role, Verdict,
};
use std::collections::{BTreeMap, BTreeSet};

const OUTPUT_SCHEMA_VERSION: u32 = 7;
const OUTPUT_SCHEMA_DIGEST: &str =
    "83ef558efc9c72b375d9f981a73285831b1936ae1e547cef0a67d9ce1d6c30bc";
const PROVIDER_CREDENTIAL_ENV: &str = "ITERON_PROVIDER_API_KEY";
const PROVIDER_CREDENTIAL_FILE: &str = "/var/run/secrets/plantcore/provider/api-key";
const MCP_URL: &str = "http://127.0.0.1:43171/mcp";
const RUN_IO_URL: &str = "http://127.0.0.1:43171/run-io/v1";
const MCP_TOKEN_ENV: &str = "PLANTCORE_RUN_GATEWAY_AUTHORIZATION";
const RUN_IO_TOKEN_FILE: &str = "/var/run/secrets/plantcore/run-io/client-token";
const MCP_CONFIG_VERSION: &str = "plantcore.mcp-config.v1";
const MAX_FACT_TEXT_BYTES: usize = 512 * 1024;
const MAX_PORTABLE_UINT: u64 = (1_u64 << 53) - 1;
const DISABLED_CATALOG_JSON: &[u8] = br#"{"revision":"disabled","tools":[]}"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlantcoreBootstrapAccepted {
    pub(crate) run_id: String,
    pub(crate) payload_digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlantcoreProtocolError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

impl PlantcoreProtocolError {
    fn invalid(message: &'static str) -> Self {
        Self {
            code: "bootstrap_invalid",
            message,
        }
    }

    fn input(message: &'static str) -> Self {
        Self {
            code: "input_invalid",
            message,
        }
    }
}

#[derive(Debug)]
enum State {
    Disabled,
    Required {
        provider_api_origin: String,
    },
    Failed,
    Admitted {
        provider_api_origin: String,
        payload: Box<PlantcoreRunBootstrapV1>,
        accepted: PlantcoreBootstrapAccepted,
        input_consumed: bool,
    },
}

#[derive(Debug)]
pub(crate) struct PlantcoreAdmission {
    state: State,
    dispatch_gate: Option<std::sync::Arc<crate::runtime::DispatchGate>>,
}

impl PlantcoreAdmission {
    pub(crate) fn disabled() -> Self {
        Self {
            state: State::Disabled,
            dispatch_gate: None,
        }
    }

    pub(crate) fn required(provider_api_origin: String) -> Self {
        Self {
            state: State::Required {
                provider_api_origin,
            },
            dispatch_gate: Some(crate::runtime::DispatchGate::new()),
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        !matches!(self.state, State::Disabled)
    }

    pub(crate) fn dispatch_gate(&self) -> Option<std::sync::Arc<crate::runtime::DispatchGate>> {
        self.dispatch_gate.clone()
    }

    pub(crate) fn admit(
        &mut self,
        payload: PlantcoreRunBootstrapV1,
        agent: &mut Agent,
        mcp: Option<&crate::mcp::McpRuntimeControl>,
    ) -> Result<PlantcoreBootstrapAccepted, PlantcoreProtocolError> {
        let provider_api_origin = match &self.state {
            State::Disabled => {
                return Err(PlantcoreProtocolError {
                    code: "bootstrap_invalid",
                    message: "PlantCore resident mode was not enabled at process launch",
                });
            }
            State::Failed => return Err(admission_failed()),
            State::Required {
                provider_api_origin,
            }
            | State::Admitted {
                provider_api_origin,
                ..
            } => provider_api_origin.clone(),
        };
        let canonical = serde_json::to_vec(&payload)
            .map_err(|_| PlantcoreProtocolError::invalid("bootstrap serialization failed"))
            .and_then(|bytes| {
                canonicalize_json(&bytes).map_err(|_| {
                    PlantcoreProtocolError::invalid("bootstrap is not portable canonical JSON")
                })
            })?;
        let accepted = PlantcoreBootstrapAccepted {
            run_id: payload.run_id.clone(),
            payload_digest_sha256: lower_sha256(&canonical),
        };
        if let State::Admitted {
            accepted: prior, ..
        } = &self.state
        {
            return replay_admission(prior, &accepted);
        }

        validate_payload(&payload, &provider_api_origin)?;
        validate_runtime(&payload, agent, mcp)?;
        if let Err(error) = apply_runtime(&payload, agent) {
            self.fail_closed();
            return Err(error);
        }
        self.state = State::Admitted {
            provider_api_origin,
            payload: Box::new(payload),
            accepted: accepted.clone(),
            input_consumed: false,
        };
        if self
            .dispatch_gate
            .as_ref()
            .is_none_or(|gate| gate.admit().is_err())
        {
            self.fail_closed();
            return Err(admission_failed());
        }
        Ok(accepted)
    }

    fn fail_closed(&mut self) {
        self.state = State::Failed;
        if let Some(gate) = &self.dispatch_gate {
            gate.terminal();
        }
    }

    pub(crate) fn admit_input(&mut self, op: &Op) -> Result<(), PlantcoreProtocolError> {
        match &mut self.state {
            State::Disabled => Ok(()),
            State::Required { .. } => Err(PlantcoreProtocolError {
                code: "bootstrap_invalid",
                message: "PlantCore bootstrap must be accepted before submissions",
            }),
            State::Failed => Err(admission_failed()),
            State::Admitted { .. }
                if !matches!(
                    op,
                    Op::UserInput { .. } | Op::UserInputV2 { .. } | Op::UserInputV3 { .. }
                ) =>
            {
                Ok(())
            }
            State::Admitted {
                payload,
                input_consumed,
                ..
            } => {
                if *input_consumed {
                    return Err(PlantcoreProtocolError::input(
                        "PlantCore resident mode accepts exactly one initial user input",
                    ));
                }
                validate_initial_input(payload, op)?;
                *input_consumed = true;
                Ok(())
            }
        }
    }
}

fn admission_failed() -> PlantcoreProtocolError {
    PlantcoreProtocolError {
        code: "bootstrap_invalid",
        message: "PlantCore bootstrap admission failed; restart the resident session",
    }
}

fn replay_admission(
    prior: &PlantcoreBootstrapAccepted,
    next: &PlantcoreBootstrapAccepted,
) -> Result<PlantcoreBootstrapAccepted, PlantcoreProtocolError> {
    if prior.payload_digest_sha256 == next.payload_digest_sha256 {
        Ok(prior.clone())
    } else {
        Err(PlantcoreProtocolError {
            code: "bootstrap_conflict",
            message: "a different PlantCore bootstrap was already accepted",
        })
    }
}

fn validate_payload(
    payload: &PlantcoreRunBootstrapV1,
    provider_api_origin: &str,
) -> Result<(), PlantcoreProtocolError> {
    if payload.contract_version != RUN_BOOTSTRAP_CONTRACT_VERSION {
        return Err(PlantcoreProtocolError::invalid(
            "unsupported PlantCore bootstrap contract version",
        ));
    }
    safe_id(&payload.run_id)?;
    let profile = &payload.agent_runtime_profile;
    safe_id(&profile.agent_definition_id)?;
    safe_id(&profile.agent_definition_version)?;
    if profile.instructions_utf8.is_empty() || profile.instructions_utf8.len() > 128 * 1024 {
        return Err(PlantcoreProtocolError::invalid(
            "Agent instructions must contain 1 through 131072 UTF-8 bytes",
        ));
    }
    require_digest(
        profile.instructions_utf8.as_bytes(),
        profile.instructions_sha256,
        "Agent instructions digest does not match",
    )?;
    require_digest(
        &encode_profile_without_digest(profile),
        profile.profile_digest_sha256,
        "Agent profile digest does not match",
    )?;
    if payload.engine.allow_code {
        return Err(PlantcoreProtocolError::invalid(
            "PlantCore G1 requires allow_code=false",
        ));
    }
    safe_id(&payload.engine.provider)?;
    safe_id(&payload.engine.model)?;

    validate_provider(payload, provider_api_origin)?;
    validate_limits(payload)?;
    validate_gateway(payload)?;
    validate_workspace(payload)?;
    validate_artifact_policy(&payload.artifact_policy)?;
    validate_conversation(payload)?;
    validate_assets(&payload.input_assets)?;
    if payload.output_schema_version != OUTPUT_SCHEMA_VERSION
        || payload.output_schema_digest_sha256.to_string() != OUTPUT_SCHEMA_DIGEST
    {
        return Err(PlantcoreProtocolError::invalid(
            "output schema version or digest is not the admitted v7 contract",
        ));
    }
    Ok(())
}

fn validate_provider(
    payload: &PlantcoreRunBootstrapV1,
    expected_api_root: &str,
) -> Result<(), PlantcoreProtocolError> {
    let provider = &payload.provider_bootstrap;
    let projected_api_root = format!("{}/v1", provider.api_origin.trim_end_matches('/'));
    if projected_api_root != expected_api_root || !is_https_origin(&provider.api_origin) {
        return Err(PlantcoreProtocolError::invalid(
            "provider API origin does not match the fixed launch route",
        ));
    }
    safe_id(&provider.policy_version)?;
    if provider.credential_env_name != PROVIDER_CREDENTIAL_ENV
        || provider.credential_projected_file != PROVIDER_CREDENTIAL_FILE
    {
        return Err(PlantcoreProtocolError::invalid(
            "provider credential projection is not the fixed G1 projection",
        ));
    }
    let material = serde_json::json!({
        "apiOrigin": provider.api_origin,
        "model": payload.engine.model,
        "provider": payload.engine.provider,
        "version": provider.policy_version,
    });
    let canonical =
        canonicalize_json(&serde_json::to_vec(&material).map_err(|_| {
            PlantcoreProtocolError::invalid("provider policy serialization failed")
        })?)
        .map_err(|_| PlantcoreProtocolError::invalid("provider policy is not canonical"))?;
    require_digest(
        &canonical,
        provider.policy_digest_sha256,
        "provider policy digest does not match",
    )
}

fn validate_limits(payload: &PlantcoreRunBootstrapV1) -> Result<(), PlantcoreProtocolError> {
    let limits = &payload.limits;
    if !(1..=64).contains(&limits.max_turns)
        || limits.max_tokens == Some(0)
        || limits
            .max_tokens
            .is_some_and(|value| value > MAX_PORTABLE_UINT)
        || limits.max_usd_micros == Some(0)
        || limits
            .max_usd_micros
            .is_some_and(|value| value > MAX_PORTABLE_UINT)
        || !(30..=3600).contains(&limits.max_wall_secs)
    {
        return Err(PlantcoreProtocolError::invalid(
            "effective Run limits are outside the admitted bounds",
        ));
    }
    require_digest(
        &encode_limits_without_digest(limits),
        limits.limits_digest_sha256,
        "effective Run limits digest does not match",
    )?;
    match (limits.max_usd_micros, &payload.metering_policy) {
        (Some(_), None) => Err(PlantcoreProtocolError::invalid(
            "a USD ceiling requires a complete metering policy",
        )),
        (_, Some(policy)) => {
            let now_unix_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| PlantcoreProtocolError::invalid("system clock predates Unix epoch"))?
                .as_millis();
            let now_unix_ms = i128::try_from(now_unix_ms).map_err(|_| {
                PlantcoreProtocolError::invalid(
                    "system clock cannot be represented in milliseconds",
                )
            })?;
            if limits.metering_policy_version.as_deref()
                != limits.max_usd_micros.map(|_| policy.version.as_str())
                || policy.provider != payload.engine.provider
                || policy.model != payload.engine.model
                || policy.effective_from_unix_ms >= policy.effective_until_unix_ms
                || now_unix_ms < i128::from(policy.effective_from_unix_ms)
                || now_unix_ms >= i128::from(policy.effective_until_unix_ms)
                || policy.calculator_contract_version != FIVE_CLASS_CALCULATOR_VERSION
                || policy.metering_unit != NATIVE_METERING_UNIT
                || [
                    policy.five_class_ceil_v1.input_units_per_million,
                    policy.five_class_ceil_v1.output_units_per_million,
                    policy.five_class_ceil_v1.cache_creation_units_per_million,
                    policy.five_class_ceil_v1.cache_read_units_per_million,
                    policy.five_class_ceil_v1.thinking_units_per_million,
                ]
                .into_iter()
                .any(|value| value > MAX_PORTABLE_UINT)
            {
                return Err(PlantcoreProtocolError::invalid(
                    "metering policy does not match the admitted engine and calculator",
                ));
            }
            safe_id(&policy.version)?;
            require_digest(
                &encode_metering_without_digest(policy),
                policy.policy_digest_sha256,
                "metering policy digest does not match",
            )
        }
        (None, None) if limits.metering_policy_version.is_some() => Err(
            PlantcoreProtocolError::invalid("effective limits name a missing metering policy"),
        ),
        (None, None) => Ok(()),
    }
}

fn validate_gateway(payload: &PlantcoreRunBootstrapV1) -> Result<(), PlantcoreProtocolError> {
    let gateway = &payload.run_gateway;
    if gateway.mcp_url != MCP_URL
        || gateway.run_io_base_url != RUN_IO_URL
        || gateway.auth_header_name != "Authorization"
        || gateway.token_env_name != MCP_TOKEN_ENV
        || gateway.mcp_config_version != MCP_CONFIG_VERSION
        || gateway.external_mcp_posture != payload.engine.external_mcp_posture
        || gateway.run_io_token_projected_file != RUN_IO_TOKEN_FILE
    {
        return Err(PlantcoreProtocolError::invalid(
            "Run Gateway bootstrap is not the fixed loopback G1 binding",
        ));
    }
    let material = serde_json::json!({
        "authHeaderName": "Authorization",
        "mcpConfigVersion": MCP_CONFIG_VERSION,
        "name": "plantcore-run-gateway",
        "tokenEnvName": MCP_TOKEN_ENV,
        "transport": "http",
        "url": MCP_URL,
    });
    let canonical = canonicalize_json(
        &serde_json::to_vec(&material)
            .map_err(|_| PlantcoreProtocolError::invalid("MCP binding serialization failed"))?,
    )
    .map_err(|_| PlantcoreProtocolError::invalid("MCP binding is not canonical"))?;
    require_digest(
        &canonical,
        gateway.mcp_config_digest_sha256,
        "MCP binding digest does not match",
    )?;
    if payload.engine.external_mcp_posture == ExternalMcpPosture::Disabled
        && (gateway.catalog_snapshot_revision != "disabled"
            || gateway.catalog_snapshot_digest_sha256 != HexSha256::digest(DISABLED_CATALOG_JSON))
    {
        return Err(PlantcoreProtocolError::invalid(
            "disabled MCP posture requires the canonical disabled catalog",
        ));
    }
    safe_id(&gateway.catalog_snapshot_revision)
}

fn validate_workspace(payload: &PlantcoreRunBootstrapV1) -> Result<(), PlantcoreProtocolError> {
    if payload.workspace.input != "/workspace/input"
        || payload.workspace.work != "/workspace/work"
        || payload.workspace.output != "/workspace/output"
    {
        return Err(PlantcoreProtocolError::invalid(
            "workspace roots are not the fixed PlantCore paths",
        ));
    }
    Ok(())
}

fn validate_artifact_policy(
    policy: &iteron_protocol::ArtifactPolicy,
) -> Result<(), PlantcoreProtocolError> {
    if policy.output_root != "/workspace/output"
        || !(1..=iteron_protocol::MAX_ARTIFACT_BYTES).contains(&policy.max_artifact_bytes)
        || !(1..=iteron_protocol::MAX_ARTIFACTS as u32).contains(&policy.max_artifact_count)
        || !(policy.max_artifact_bytes..=iteron_protocol::MAX_TOTAL_ARTIFACT_BYTES)
            .contains(&policy.max_total_artifact_bytes)
        || !(1..=iteron_protocol::MAX_UPLOAD_CHUNK_BYTES).contains(&policy.max_upload_chunk_bytes)
        || u64::from(policy.max_upload_chunk_bytes) > policy.max_artifact_bytes
        || policy.required_artifacts.len() > policy.max_artifact_count as usize
    {
        return Err(PlantcoreProtocolError::invalid(
            "artifact policy is outside the admitted G1 bounds",
        ));
    }
    let mut logical_names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for requirement in &policy.required_artifacts {
        if !logical_names.insert(&requirement.logical_name)
            || !paths.insert(&requirement.relative_path)
            || requirement.allowed_media_types.is_empty()
            || requirement.allowed_media_types.len() > 16
            || !(1..=policy.max_artifact_bytes).contains(&requirement.max_size_bytes)
        {
            return Err(PlantcoreProtocolError::invalid(
                "artifact requirements are not unique or bounded",
            ));
        }
        safe_id(&requirement.logical_name)?;
        safe_relative_path(&requirement.relative_path)?;
        let mut media_types = BTreeSet::new();
        for media_type in &requirement.allowed_media_types {
            if media_type.is_empty()
                || media_type.len() > 128
                || media_type.bytes().any(|byte| {
                    byte.is_ascii_uppercase()
                        || byte.is_ascii_control()
                        || byte.is_ascii_whitespace()
                })
                || !media_types.insert(media_type)
            {
                return Err(PlantcoreProtocolError::invalid(
                    "artifact requirement media types are not canonical",
                ));
            }
        }
    }
    require_digest(
        &encode_artifact_policy_without_digest(policy),
        policy.policy_digest_sha256,
        "artifact policy digest does not match",
    )
}

fn validate_conversation(payload: &PlantcoreRunBootstrapV1) -> Result<(), PlantcoreProtocolError> {
    safe_id(&payload.current_user_input.source_run_id)?;
    safe_id(&payload.current_user_input.source_message_id)?;
    let mut previous = 0;
    let mut current_matches = 0;
    let mut fact_text_bytes = 0usize;
    let mut actions = BTreeMap::<(&str, HexSha256), ActionDecision>::new();
    let mut action_results = BTreeSet::<(&str, HexSha256)>::new();
    for segment in &payload.conversation_segments {
        if segment.sequence == 0 || segment.sequence <= previous {
            return Err(PlantcoreProtocolError::invalid(
                "conversation sequence must be positive and strictly increasing",
            ));
        }
        previous = segment.sequence;
        safe_id(&segment.source_run_id)?;
        let encoded = encode_fact(&segment.fact)?;
        require_digest(
            &encoded,
            segment.fact_digest_sha256,
            "conversation fact digest does not match",
        )?;
        match &segment.fact {
            ConversationFact::UserMessage {
                content_utf8,
                content_sha256,
                source_message_id,
            }
            | ConversationFact::AssistantMessage {
                content_utf8,
                content_sha256,
                source_message_id,
            } => {
                safe_id(source_message_id)?;
                require_digest(
                    content_utf8.as_bytes(),
                    *content_sha256,
                    "conversation text digest does not match",
                )?;
                fact_text_bytes = fact_text_bytes.saturating_add(content_utf8.len());
                if matches!(segment.fact, ConversationFact::UserMessage { .. })
                    && segment.sequence == payload.current_user_input.conversation_sequence
                    && segment.source_run_id == payload.current_user_input.source_run_id
                    && *source_message_id == payload.current_user_input.source_message_id
                    && *content_sha256 == payload.current_user_input.content_sha256
                {
                    current_matches += 1;
                }
            }
            ConversationFact::QuestionAnswer {
                question_id,
                answer_utf8,
                answer_sha256,
                answered_by_actor_id,
                ..
            } => {
                safe_id(question_id)?;
                safe_id(answered_by_actor_id)?;
                require_digest(
                    answer_utf8.as_bytes(),
                    *answer_sha256,
                    "question answer digest does not match",
                )?;
                fact_text_bytes = fact_text_bytes.saturating_add(answer_utf8.len());
            }
            ConversationFact::ActionDecision {
                action_review_id,
                action_digest_sha256,
                decision,
                decided_by_actor_id,
                ..
            } => {
                safe_id(action_review_id)?;
                if let Some(actor_id) = decided_by_actor_id {
                    safe_id(actor_id)?;
                }
                if (*decision == ActionDecision::Expired) != decided_by_actor_id.is_none() {
                    return Err(PlantcoreProtocolError::invalid(
                        "action decision actor presence is inconsistent with expiry",
                    ));
                }
                if actions
                    .insert((action_review_id, *action_digest_sha256), *decision)
                    .is_some()
                {
                    return Err(PlantcoreProtocolError::invalid(
                        "conversation repeats an action decision",
                    ));
                }
            }
            ConversationFact::ActionResult {
                action_review_id,
                action_digest_sha256,
                safe_summary_utf8,
                result_digest_sha256,
                connector_journal_id,
                ..
            } => {
                safe_id(action_review_id)?;
                safe_id(connector_journal_id)?;
                if actions.get(&(action_review_id, *action_digest_sha256))
                    != Some(&ActionDecision::Approved)
                    || !action_results.insert((action_review_id, *action_digest_sha256))
                {
                    return Err(PlantcoreProtocolError::invalid(
                        "action result lacks exactly one preceding approved decision",
                    ));
                }
                require_digest(
                    safe_summary_utf8.as_bytes(),
                    *result_digest_sha256,
                    "action result summary digest does not match",
                )?;
                fact_text_bytes = fact_text_bytes.saturating_add(safe_summary_utf8.len());
            }
        }
        if fact_text_bytes > MAX_FACT_TEXT_BYTES {
            return Err(PlantcoreProtocolError::invalid(
                "conversation fact text exceeds 524288 UTF-8 bytes",
            ));
        }
    }
    for (identity, decision) in actions {
        if decision == ActionDecision::Approved && !action_results.contains(&identity) {
            return Err(PlantcoreProtocolError::invalid(
                "approved action decision requires exactly one later result",
            ));
        }
    }
    if current_matches != 1 {
        return Err(PlantcoreProtocolError::invalid(
            "current user input must identify exactly one user message fact",
        ));
    }
    Ok(())
}

fn validate_assets(assets: &[InputAssetRef]) -> Result<(), PlantcoreProtocolError> {
    let mut handles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut text_count = 0usize;
    let mut image_count = 0usize;
    let mut file_bytes = 0u64;
    let mut image_base64_bytes = 0u64;
    if assets.len() > 16 {
        return Err(PlantcoreProtocolError::invalid(
            "input assets exceed the admitted count or byte bounds",
        ));
    }
    for asset in assets {
        safe_id(&asset.asset_handle)?;
        safe_relative_path(&asset.relative_path)?;
        if asset.media_type.is_empty()
            || asset.media_type.len() > 128
            || asset.size_bytes > MAX_PORTABLE_UINT
        {
            return Err(PlantcoreProtocolError::invalid(
                "input asset media type or size is outside the admitted bounds",
            ));
        }
        if !handles.insert(&asset.asset_handle) || !paths.insert(&asset.relative_path) {
            return Err(PlantcoreProtocolError::invalid(
                "input assets must have unique handles and paths",
            ));
        }
        match asset.materialization {
            InputMaterialization::ImageAttachment => {
                image_count += 1;
                if !matches!(
                    asset.media_type.as_str(),
                    "image/png" | "image/jpeg" | "image/gif" | "image/webp"
                ) {
                    return Err(PlantcoreProtocolError::invalid(
                        "image asset media type is not supported by the input protocol",
                    ));
                }
                let encoded_bytes = asset
                    .size_bytes
                    .checked_add(2)
                    .map(|bytes| bytes / 3 * 4)
                    .ok_or_else(|| {
                        PlantcoreProtocolError::invalid(
                            "input assets exceed the admitted count or byte bounds",
                        )
                    })?;
                image_base64_bytes = image_base64_bytes.saturating_add(encoded_bytes);
            }
            InputMaterialization::TextAttachment => {
                text_count += 1;
                file_bytes = file_bytes.saturating_add(asset.size_bytes);
            }
            InputMaterialization::WorkspaceReadOnly => {
                file_bytes = file_bytes.saturating_add(asset.size_bytes);
            }
        }
    }
    if text_count > MAX_INPUT_FILES
        || image_count > MAX_INPUT_IMAGES
        || file_bytes > MAX_TOTAL_FILE_TEXT_BYTES as u64
        || image_base64_bytes > MAX_TOTAL_IMAGE_BASE64_BYTES as u64
    {
        return Err(PlantcoreProtocolError::invalid(
            "input assets exceed the admitted count or byte bounds",
        ));
    }
    Ok(())
}

fn validate_runtime(
    payload: &PlantcoreRunBootstrapV1,
    agent: &Agent,
    mcp: Option<&crate::mcp::McpRuntimeControl>,
) -> Result<(), PlantcoreProtocolError> {
    if agent.provider.provider_instance_id() != Some(payload.engine.provider.as_str())
        || agent.model != payload.engine.model
    {
        return Err(PlantcoreProtocolError::invalid(
            "bootstrap provider/model does not match the fixed launch route",
        ));
    }
    if agent.workspace != std::path::Path::new(&payload.workspace.work) {
        return Err(PlantcoreProtocolError::invalid(
            "runtime workspace does not match the fixed bootstrap workspace",
        ));
    }
    match (payload.engine.external_mcp_posture, mcp) {
        (ExternalMcpPosture::Disabled, None) => Ok(()),
        (ExternalMcpPosture::Disabled, Some(runtime)) if runtime.health().is_empty() => Ok(()),
        (ExternalMcpPosture::RunGateway, Some(runtime)) => {
            if runtime.is_exact_plantcore_run_gateway(MCP_URL, MCP_TOKEN_ENV) {
                Ok(())
            } else {
                Err(PlantcoreProtocolError::invalid(
                    "runtime MCP binding is not the fixed PlantCore Run Gateway",
                ))
            }
        }
        _ => Err(PlantcoreProtocolError::invalid(
            "runtime MCP configuration does not match the bootstrap posture",
        )),
    }
}

fn apply_runtime(
    payload: &PlantcoreRunBootstrapV1,
    agent: &mut Agent,
) -> Result<(), PlantcoreProtocolError> {
    crate::runtime::hooks::Hooks::preflight_plantcore_workspace_gate().map_err(|_| {
        PlantcoreProtocolError::invalid("could not install fixed PlantCore workspace Hook")
    })?;
    agent
        .freeze_plantcore_provider_identity(&payload.engine.provider, &payload.engine.model)
        .map_err(|_| {
            PlantcoreProtocolError::invalid("could not freeze the PlantCore provider identity")
        })?;
    agent
        .registry
        .register_plantcore_tools()
        .map_err(|_| PlantcoreProtocolError::invalid("could not register fixed PlantCore tools"))?;
    agent.enable_plantcore_runtime(payload).map_err(|_| {
        PlantcoreProtocolError::invalid("could not preserve typed conversation facts")
    })?;
    agent
        .hooks
        .install_plantcore_workspace_gate(payload.engine.builtin_workspace_posture)
        .map_err(|_| {
            PlantcoreProtocolError::invalid("could not install fixed PlantCore workspace Hook")
        })?;
    agent.system = payload.agent_runtime_profile.instructions_utf8.clone();
    agent.system_trust = iteron_protocol::Trust::Trusted;
    agent
        .transition_turn_ceiling(
            payload.limits.max_turns,
            iteron_protocol::RuntimePolicySource::Harness,
        )
        .map_err(|_| PlantcoreProtocolError::invalid("could not freeze the turn ceiling"))?;
    agent.budget.max_tokens = payload.limits.max_tokens;
    // PlantCore's native USD_MICRO ceiling is enforced by the exact five-class integer
    // calculator. Do not also route it through Iteron's legacy floating-point rate-card budget.
    agent.budget.max_usd = None;
    agent.budget.max_wall_secs = u64::from(payload.limits.max_wall_secs);
    agent.budget.max_consecutive_tool_errors = 5;
    agent.compaction.enabled = false;
    agent
        .transition_effort(
            map_effort(payload.engine.effort),
            iteron_protocol::RuntimePolicySource::Harness,
        )
        .map_err(|_| PlantcoreProtocolError::invalid("could not freeze Agent effort"))?;
    let permission_mode = match payload.engine.builtin_workspace_posture {
        BuiltinWorkspacePosture::ReadOnly => PermissionMode::Plan,
        BuiltinWorkspacePosture::ReadWrite => PermissionMode::AcceptEdits,
    };
    let mut permission_rules = PermissionRules::new();
    permission_rules.set_cap(Capability::CodeExecuting, Verdict::Deny);
    agent
        .transition_permission_policy(
            permission_mode,
            permission_rules,
            iteron_protocol::RuntimePolicySource::Harness,
        )
        .map_err(|_| PlantcoreProtocolError::invalid("could not freeze workspace posture"))?;
    agent
        .transition_permission_capability_rule(
            Capability::CodeExecuting,
            Verdict::Deny,
            iteron_protocol::RuntimePolicySource::Harness,
        )
        .map_err(|_| PlantcoreProtocolError::invalid("could not enforce allow_code=false"))?;
    let history = history_messages_from_segments(
        agent.plantcore_conversation_segments(),
        payload.current_user_input.conversation_sequence,
    )?;
    agent
        .set_resume(history)
        .map_err(|_| PlantcoreProtocolError::invalid("could not install typed conversation"))?;
    if !agent.ui(crate::runtime::UiEvent::PlantcoreRunAdmitted {
        profile_digest_sha256: payload.agent_runtime_profile.profile_digest_sha256,
    }) {
        return Err(PlantcoreProtocolError::invalid(
            "could not publish the admitted Agent profile digest",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn history_messages(
    payload: &PlantcoreRunBootstrapV1,
) -> Result<Vec<Message>, PlantcoreProtocolError> {
    history_messages_from_segments(
        &payload.conversation_segments,
        payload.current_user_input.conversation_sequence,
    )
}

fn history_messages_from_segments(
    segments: &[iteron_protocol::ConversationSegment],
    current_user_sequence: u64,
) -> Result<Vec<Message>, PlantcoreProtocolError> {
    let mut messages = Vec::with_capacity(segments.len());
    for segment in segments.iter().filter(|segment| {
        segment.sequence != current_user_sequence
            || !matches!(segment.fact, ConversationFact::UserMessage { .. })
    }) {
        let message = match &segment.fact {
            ConversationFact::UserMessage { content_utf8, .. } => {
                Some(Message::user_text(content_utf8.clone()))
            }
            ConversationFact::AssistantMessage { content_utf8, .. } => Some(Message {
                role: Role::Assistant,
                content: vec![Block::Text {
                    text: content_utf8.clone(),
                }],
            }),
            ConversationFact::QuestionAnswer { .. }
            | ConversationFact::ActionDecision { .. }
            | ConversationFact::ActionResult { .. } => {
                let text = serde_json::to_string(&serde_json::json!({
                    "contract": "plantcore.conversation-segment.v1",
                    "segment": segment,
                }))
                .map_err(|_| {
                    PlantcoreProtocolError::invalid(
                        "typed conversation fact could not be projected",
                    )
                })?;
                Some(Message::user_text(text))
            }
        };
        if let Some(message) = message {
            messages.push(message);
        }
    }
    Ok(messages)
}

fn validate_initial_input(
    payload: &PlantcoreRunBootstrapV1,
    op: &Op,
) -> Result<(), PlantcoreProtocolError> {
    let expected_text = payload
        .conversation_segments
        .iter()
        .find_map(|segment| {
            (segment.sequence == payload.current_user_input.conversation_sequence)
                .then_some(&segment.fact)
                .and_then(|fact| match fact {
                    ConversationFact::UserMessage { content_utf8, .. } => Some(content_utf8),
                    _ => None,
                })
        })
        .ok_or_else(|| PlantcoreProtocolError::input("current user message is absent"))?;
    let (actual_text, images, files): (&str, Vec<_>, &[_]) = match op {
        Op::UserInput { text } => (text, Vec::new(), &[]),
        Op::UserInputV2 { segments } => (segments.text(), segments.images().collect(), &[]),
        Op::UserInputV3 {
            text,
            images,
            files,
        } => (text, images.iter().collect(), files),
        _ => return Ok(()),
    };
    if actual_text != expected_text
        || HexSha256::digest(actual_text.as_bytes()) != payload.current_user_input.content_sha256
    {
        return Err(PlantcoreProtocolError::input(
            "initial user text does not match the bootstrap current source",
        ));
    }
    let expected_images: Vec<_> = payload
        .input_assets
        .iter()
        .filter(|asset| asset.materialization == InputMaterialization::ImageAttachment)
        .collect();
    let expected_files: Vec<_> = payload
        .input_assets
        .iter()
        .filter(|asset| asset.materialization == InputMaterialization::TextAttachment)
        .collect();
    if images.len() != expected_images.len() || files.len() != expected_files.len() {
        return Err(PlantcoreProtocolError::input(
            "initial input attachment count does not match bootstrap metadata",
        ));
    }
    for (image, expected) in images.into_iter().zip(expected_images) {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(image.data.as_str())
            .map_err(|_| PlantcoreProtocolError::input("initial image is not canonical base64"))?;
        if image.media_type.as_str() != expected.media_type
            || decoded.len() as u64 != expected.size_bytes
            || HexSha256::digest(&decoded) != expected.content_sha256
        {
            return Err(PlantcoreProtocolError::input(
                "initial image bytes, size, media type, or digest do not match bootstrap metadata",
            ));
        }
    }
    for (file, expected) in files.iter().zip(expected_files) {
        if file.path != expected.relative_path
            || file.text.len() as u64 != expected.size_bytes
            || HexSha256::digest(file.text.as_bytes()) != expected.content_sha256
        {
            return Err(PlantcoreProtocolError::input(
                "initial file path, bytes, size, or digest do not match bootstrap metadata",
            ));
        }
    }
    Ok(())
}

fn safe_id(value: &str) -> Result<(), PlantcoreProtocolError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(PlantcoreProtocolError::invalid(
            "bootstrap contains an invalid stable identifier",
        ));
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> Result<(), PlantcoreProtocolError> {
    let path = std::path::Path::new(value);
    if value.is_empty()
        || value.len() > 1024
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(PlantcoreProtocolError::invalid(
            "input asset path is not a safe relative path",
        ));
    }
    Ok(())
}

fn is_https_origin(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        value.len() <= 2048
            && url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn require_digest(
    bytes: &[u8],
    digest: HexSha256,
    message: &'static str,
) -> Result<(), PlantcoreProtocolError> {
    if HexSha256::digest(bytes) != digest {
        return Err(PlantcoreProtocolError::invalid(message));
    }
    Ok(())
}

fn map_effort(value: EngineEffort) -> Effort {
    match value {
        EngineEffort::Low => Effort::Low,
        EngineEffort::Medium => Effort::Medium,
        EngineEffort::High => Effort::High,
        EngineEffort::Xhigh => Effort::XHigh,
        EngineEffort::Max => Effort::Max,
        EngineEffort::Ultracode => Effort::Ultracode,
    }
}

fn encode_profile_without_digest(profile: &iteron_protocol::AgentRuntimeProfile) -> Vec<u8> {
    let mut encoded = Vec::new();
    field_string(&mut encoded, 1, &profile.agent_definition_id);
    field_string(&mut encoded, 2, &profile.agent_definition_version);
    field_string(&mut encoded, 3, &profile.instructions_utf8);
    field_bytes(&mut encoded, 4, &profile.instructions_sha256.into_bytes());
    field_bytes(
        &mut encoded,
        5,
        &profile.capability_policy_digest_sha256.into_bytes(),
    );
    encoded
}

fn encode_limits_without_digest(limits: &iteron_protocol::EffectiveRunLimits) -> Vec<u8> {
    let mut encoded = Vec::new();
    field_varint(&mut encoded, 1, u64::from(limits.max_turns));
    if let Some(value) = limits.max_tokens {
        field_varint(&mut encoded, 2, value);
    }
    if let Some(value) = limits.max_usd_micros {
        field_varint(&mut encoded, 3, value);
    }
    field_varint(&mut encoded, 4, u64::from(limits.max_wall_secs));
    if let Some(value) = &limits.metering_policy_version {
        field_string(&mut encoded, 6, value);
    }
    encoded
}

fn encode_metering_without_digest(policy: &iteron_protocol::MeteringPolicySnapshot) -> Vec<u8> {
    let mut encoded = Vec::new();
    field_string(&mut encoded, 1, &policy.version);
    field_string(&mut encoded, 2, &policy.provider);
    field_string(&mut encoded, 3, &policy.model);
    for (number, value) in [
        (4, policy.effective_from_unix_ms),
        (5, policy.effective_until_unix_ms),
    ] {
        if value != 0 {
            field_varint(&mut encoded, number, value as u64);
        }
    }
    field_string(&mut encoded, 6, &policy.calculator_contract_version);
    field_string(&mut encoded, 7, &policy.metering_unit);
    let rates = &policy.five_class_ceil_v1;
    let mut parameters = Vec::new();
    for (number, value) in [
        (1, rates.input_units_per_million),
        (2, rates.output_units_per_million),
        (3, rates.cache_creation_units_per_million),
        (4, rates.cache_read_units_per_million),
        (5, rates.thinking_units_per_million),
    ] {
        if value != 0 {
            field_varint(&mut parameters, number, value);
        }
    }
    field_bytes(&mut encoded, 20, &parameters);
    encoded
}

fn encode_artifact_policy_without_digest(policy: &iteron_protocol::ArtifactPolicy) -> Vec<u8> {
    let mut encoded = Vec::new();
    field_string(&mut encoded, 1, &policy.output_root);
    field_varint(&mut encoded, 2, policy.max_artifact_bytes);
    field_varint(&mut encoded, 3, u64::from(policy.max_artifact_count));
    field_varint(&mut encoded, 4, policy.max_total_artifact_bytes);
    field_varint(&mut encoded, 5, u64::from(policy.max_upload_chunk_bytes));
    for requirement in &policy.required_artifacts {
        let mut nested = Vec::new();
        field_string(&mut nested, 1, &requirement.logical_name);
        field_string(&mut nested, 2, &requirement.relative_path);
        for media_type in &requirement.allowed_media_types {
            field_string(&mut nested, 3, media_type);
        }
        field_varint(&mut nested, 4, requirement.max_size_bytes);
        field_bytes(&mut encoded, 6, &nested);
    }
    encoded
}

fn encode_fact(fact: &ConversationFact) -> Result<Vec<u8>, PlantcoreProtocolError> {
    let mut encoded = Vec::new();
    match fact {
        ConversationFact::UserMessage {
            content_utf8,
            content_sha256,
            source_message_id,
        }
        | ConversationFact::AssistantMessage {
            content_utf8,
            content_sha256,
            source_message_id,
        } => {
            field_string(&mut encoded, 1, content_utf8);
            field_bytes(&mut encoded, 2, &content_sha256.into_bytes());
            field_string(&mut encoded, 3, source_message_id);
        }
        ConversationFact::QuestionAnswer {
            question_id,
            question_digest_sha256,
            answer_utf8,
            answer_sha256,
            answered_by_actor_id,
            answered_at_unix_ms,
        } => {
            field_string(&mut encoded, 1, question_id);
            field_bytes(&mut encoded, 2, &question_digest_sha256.into_bytes());
            field_string(&mut encoded, 3, answer_utf8);
            field_bytes(&mut encoded, 4, &answer_sha256.into_bytes());
            field_string(&mut encoded, 5, answered_by_actor_id);
            field_varint(&mut encoded, 6, *answered_at_unix_ms as u64);
        }
        ConversationFact::ActionDecision {
            action_review_id,
            action_digest_sha256,
            decision,
            decided_by_actor_id,
            decided_at_unix_ms,
        } => {
            field_string(&mut encoded, 1, action_review_id);
            field_bytes(&mut encoded, 2, &action_digest_sha256.into_bytes());
            field_varint(
                &mut encoded,
                3,
                match decision {
                    ActionDecision::Approved => 1,
                    ActionDecision::Rejected => 2,
                    ActionDecision::Expired => 3,
                },
            );
            if let Some(actor) = decided_by_actor_id {
                field_string(&mut encoded, 4, actor);
            }
            field_varint(&mut encoded, 5, *decided_at_unix_ms as u64);
        }
        ConversationFact::ActionResult {
            action_review_id,
            action_digest_sha256,
            status,
            safe_summary_utf8,
            result_digest_sha256,
            connector_journal_id,
            completed_at_unix_ms,
        } => {
            field_string(&mut encoded, 1, action_review_id);
            field_bytes(&mut encoded, 2, &action_digest_sha256.into_bytes());
            field_varint(
                &mut encoded,
                3,
                match status {
                    ActionEffectStatus::Succeeded => 1,
                    ActionEffectStatus::Failed => 2,
                    ActionEffectStatus::UnknownEffect => 3,
                },
            );
            field_string(&mut encoded, 4, safe_summary_utf8);
            field_bytes(&mut encoded, 5, &result_digest_sha256.into_bytes());
            field_string(&mut encoded, 6, connector_journal_id);
            field_varint(&mut encoded, 7, *completed_at_unix_ms as u64);
        }
    }
    Ok(encoded)
}

fn field_string(output: &mut Vec<u8>, number: u64, value: &str) {
    field_bytes(output, number, value.as_bytes());
}

fn field_bytes(output: &mut Vec<u8>, number: u64, value: &[u8]) {
    varint(output, (number << 3) | 2);
    varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn field_varint(output: &mut Vec<u8>, number: u64, value: u64) {
    varint(output, number << 3);
    varint(output, value);
}

fn varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IdentifiedTestProvider;

    #[async_trait::async_trait]
    impl iteron_provider::Provider for IdentifiedTestProvider {
        fn provider_instance_id(&self) -> Option<&str> {
            Some("plantcore")
        }

        async fn turn(
            &self,
            _request: &iteron_provider::TurnRequest,
            _on_item: &mut (dyn FnMut(iteron_provider::StreamItem) + Send),
        ) -> Result<iteron_provider::TurnResult, iteron_provider::ProviderError> {
            unreachable!("bootstrap admission does not dispatch the Provider")
        }
    }

    fn app_server_schema() -> jsonschema::Validator {
        let schema = serde_json::from_slice(include_bytes!(
            "../../../../contracts/plantcore/app-server-v4.schema.json"
        ))
        .unwrap();
        jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .build(&schema)
            .unwrap()
    }

    fn payload() -> PlantcoreRunBootstrapV1 {
        let content = "hello";
        let mut limits = iteron_protocol::EffectiveRunLimits {
            max_turns: 8,
            max_tokens: Some(1_000),
            max_usd_micros: None,
            max_wall_secs: 300,
            metering_policy_version: None,
            limits_digest_sha256: HexSha256::digest(b"unset"),
        };
        limits.limits_digest_sha256 = HexSha256::digest(&encode_limits_without_digest(&limits));
        let mut artifact_policy = iteron_protocol::ArtifactPolicy {
            output_root: "/workspace/output".into(),
            max_artifact_bytes: iteron_protocol::MAX_ARTIFACT_BYTES,
            max_artifact_count: iteron_protocol::MAX_ARTIFACTS as u32,
            max_total_artifact_bytes: iteron_protocol::MAX_TOTAL_ARTIFACT_BYTES,
            max_upload_chunk_bytes: iteron_protocol::MAX_UPLOAD_CHUNK_BYTES,
            required_artifacts: Vec::new(),
            policy_digest_sha256: HexSha256::digest(b"unset"),
        };
        artifact_policy.policy_digest_sha256 =
            HexSha256::digest(&encode_artifact_policy_without_digest(&artifact_policy));
        let mut profile = iteron_protocol::AgentRuntimeProfile {
            agent_definition_id: "agent-1".into(),
            agent_definition_version: "v1".into(),
            instructions_utf8: "system".into(),
            instructions_sha256: HexSha256::digest(b"system"),
            capability_policy_digest_sha256: HexSha256::digest(b"capability"),
            profile_digest_sha256: HexSha256::digest(b"unset"),
        };
        profile.profile_digest_sha256 = HexSha256::digest(&encode_profile_without_digest(&profile));
        let mut provider_bootstrap = iteron_protocol::ProviderBootstrap {
            api_origin: "https://provider.example/".into(),
            policy_version: "policy-v1".into(),
            policy_digest_sha256: HexSha256::digest(b"unset"),
            credential_env_name: PROVIDER_CREDENTIAL_ENV.into(),
            credential_projected_file: PROVIDER_CREDENTIAL_FILE.into(),
        };
        let provider_material = serde_json::json!({
            "apiOrigin": provider_bootstrap.api_origin,
            "model": "qwen",
            "provider": "plantcore",
            "version": provider_bootstrap.policy_version,
        });
        provider_bootstrap.policy_digest_sha256 = HexSha256::digest(
            &canonicalize_json(&serde_json::to_vec(&provider_material).unwrap()).unwrap(),
        );
        let mut run_gateway = iteron_protocol::RunGatewayBootstrap {
            mcp_url: MCP_URL.into(),
            run_io_base_url: RUN_IO_URL.into(),
            auth_header_name: "Authorization".into(),
            token_env_name: MCP_TOKEN_ENV.into(),
            mcp_config_version: MCP_CONFIG_VERSION.into(),
            mcp_config_digest_sha256: HexSha256::digest(b"unset"),
            catalog_snapshot_digest_sha256: HexSha256::digest(DISABLED_CATALOG_JSON),
            catalog_snapshot_revision: "disabled".into(),
            external_mcp_posture: ExternalMcpPosture::Disabled,
            run_io_token_projected_file: RUN_IO_TOKEN_FILE.into(),
        };
        let gateway_material = serde_json::json!({
            "authHeaderName": "Authorization",
            "mcpConfigVersion": MCP_CONFIG_VERSION,
            "name": "plantcore-run-gateway",
            "tokenEnvName": MCP_TOKEN_ENV,
            "transport": "http",
            "url": MCP_URL,
        });
        run_gateway.mcp_config_digest_sha256 = HexSha256::digest(
            &canonicalize_json(&serde_json::to_vec(&gateway_material).unwrap()).unwrap(),
        );
        let fact = ConversationFact::UserMessage {
            content_utf8: content.into(),
            content_sha256: HexSha256::digest(content.as_bytes()),
            source_message_id: "message-1".into(),
        };
        let fact_digest_sha256 = HexSha256::digest(&encode_fact(&fact).unwrap());
        PlantcoreRunBootstrapV1 {
            contract_version: RUN_BOOTSTRAP_CONTRACT_VERSION.into(),
            run_id: "run-1".into(),
            agent_runtime_profile: profile,
            engine: iteron_protocol::PlantcoreEngineSpec {
                provider: "plantcore".into(),
                model: "qwen".into(),
                effort: EngineEffort::High,
                allow_code: false,
                builtin_workspace_posture: BuiltinWorkspacePosture::ReadWrite,
                external_mcp_posture: ExternalMcpPosture::Disabled,
            },
            provider_bootstrap,
            run_gateway,
            limits,
            metering_policy: None,
            output_schema_version: OUTPUT_SCHEMA_VERSION,
            output_schema_digest_sha256: OUTPUT_SCHEMA_DIGEST.parse().unwrap(),
            workspace: iteron_protocol::WorkspaceRoots {
                input: "/workspace/input".into(),
                work: "/workspace/work".into(),
                output: "/workspace/output".into(),
            },
            artifact_policy,
            conversation_segments: vec![iteron_protocol::ConversationSegment {
                sequence: 1,
                source_run_id: "source-run".into(),
                fact_digest_sha256,
                fact,
            }],
            current_user_input: iteron_protocol::CurrentUserInputSource {
                conversation_sequence: 1,
                source_run_id: "source-run".into(),
                source_message_id: "message-1".into(),
                content_sha256: HexSha256::digest(content.as_bytes()),
            },
            input_assets: Vec::new(),
        }
    }

    #[test]
    fn required_mode_rejects_input_before_bootstrap() {
        let mut admission = PlantcoreAdmission::required("https://provider.example/".into());
        let error = admission
            .admit_input(&Op::UserInput { text: "hi".into() })
            .unwrap_err();
        assert_eq!(error.code, "bootstrap_invalid");
        assert_eq!(
            admission
                .admit_input(&Op::Steer {
                    text: "early".into()
                })
                .unwrap_err()
                .code,
            "bootstrap_invalid"
        );
    }

    #[test]
    fn invalid_initial_input_does_not_consume_the_valid_retry() {
        let payload = payload();
        let mut admission = PlantcoreAdmission {
            state: State::Admitted {
                provider_api_origin: "https://provider.example/v1".into(),
                payload: Box::new(payload),
                accepted: PlantcoreBootstrapAccepted {
                    run_id: "run-1".into(),
                    payload_digest_sha256: HexSha256::digest(b"bootstrap").to_lower_hex(),
                },
                input_consumed: false,
            },
            dispatch_gate: None,
        };

        assert_eq!(
            admission
                .admit_input(&Op::UserInput {
                    text: "wrong".into(),
                })
                .unwrap_err()
                .code,
            "input_invalid"
        );
        assert_eq!(
            admission.admit_input(&Op::UserInput {
                text: "hello".into(),
            }),
            Ok(())
        );
        assert_eq!(
            admission
                .admit_input(&Op::UserInput {
                    text: "hello".into(),
                })
                .unwrap_err()
                .code,
            "input_invalid"
        );
    }

    #[test]
    fn late_bootstrap_apply_failure_terminalizes_the_shared_gate() {
        let workspace = std::env::temp_dir().join(format!(
            "iteron-plantcore-bootstrap-failure-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&workspace).unwrap();
        let rollout = iteron_record::Rollout::open(
            &workspace.join("runs"),
            &iteron_protocol::RunId("run-1".into()),
            iteron_protocol::TenantId::default(),
        )
        .unwrap();
        let mut agent = Agent::new(
            std::sync::Arc::new(IdentifiedTestProvider),
            iteron_tools::Registry::coding_agent(&workspace).unwrap(),
            rollout,
            "qwen".into(),
            "startup".into(),
            iteron_protocol::Budget {
                max_turns: 4,
                max_usd: None,
                max_tokens: None,
                max_wall_secs: 300,
                max_consecutive_tool_errors: 5,
            },
        );
        agent.workspace = "/workspace/work".into();
        agent.fail_next_plantcore_bootstrap_append_for_test();

        let mut admission = PlantcoreAdmission::required("https://provider.example/v1".into());
        let gate = admission.dispatch_gate().unwrap();
        agent.install_plantcore_dispatch_gate(gate.clone());
        let error = admission.admit(payload(), &mut agent, None).unwrap_err();
        assert_eq!(error.message, "could not freeze the turn ceiling");
        assert_eq!(
            gate.submit_if_admitted(|| Ok::<_, ()>(())),
            Err("session_terminal")
        );
        assert_eq!(
            admission
                .admit_input(&Op::UserInput {
                    text: "late".into()
                })
                .unwrap_err()
                .message,
            "PlantCore bootstrap admission failed; restart the resident session"
        );
        assert_eq!(
            admission
                .admit_input(&Op::Steer {
                    text: "late".into()
                })
                .unwrap_err()
                .message,
            "PlantCore bootstrap admission failed; restart the resident session"
        );
        assert_eq!(
            admission
                .admit(payload(), &mut agent, None)
                .unwrap_err()
                .message,
            "PlantCore bootstrap admission failed; restart the resident session"
        );

        drop(agent);
        std::fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn complete_bootstrap_payload_passes_all_release_admission_checks() {
        let fixture = payload();
        assert_eq!(
            validate_payload(&fixture, "https://provider.example/v1"),
            Ok(())
        );
        let encoded = serde_json::to_value(&fixture).unwrap();
        let mut unknown_effort = encoded.clone();
        unknown_effort["engine"]["effort"] = serde_json::Value::from("future");
        assert!(
            serde_json::from_value::<PlantcoreRunBootstrapV1>(unknown_effort).is_err(),
            "unknown security-critical enums must fail during wire decoding"
        );
        let mut unknown_field = encoded;
        unknown_field["artifact_policy"]["future_quota"] = serde_json::Value::from(1);
        assert!(serde_json::from_value::<PlantcoreRunBootstrapV1>(unknown_field).is_err());
    }

    #[test]
    fn disabled_gateway_requires_the_canonical_empty_catalog() {
        let mut fixture = payload();
        assert_eq!(validate_gateway(&fixture), Ok(()));
        fixture.run_gateway.catalog_snapshot_digest_sha256 = HexSha256::digest(b"placeholder");
        assert_eq!(
            validate_gateway(&fixture).unwrap_err().message,
            "disabled MCP posture requires the canonical disabled catalog"
        );
    }

    #[test]
    fn input_assets_enforce_independent_text_image_and_total_bounds() {
        let asset = |handle: &str, size_bytes, materialization| InputAssetRef {
            asset_handle: handle.into(),
            relative_path: format!("{handle}.bin"),
            media_type: if materialization == InputMaterialization::ImageAttachment {
                "image/png"
            } else {
                "application/octet-stream"
            }
            .into(),
            size_bytes,
            content_sha256: HexSha256::digest(handle.as_bytes()),
            materialization,
        };
        assert_eq!(
            validate_assets(&[asset("empty-text", 0, InputMaterialization::TextAttachment)]),
            Ok(())
        );
        assert!(
            validate_assets(&[asset(
                "large-image",
                (MAX_TOTAL_IMAGE_BASE64_BYTES as u64 / 4 * 3) + 1,
                InputMaterialization::ImageAttachment
            )])
            .is_err()
        );
        let workspace_assets = (0..16)
            .map(|index| {
                asset(
                    &format!("workspace-{index}"),
                    1,
                    InputMaterialization::WorkspaceReadOnly,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(validate_assets(&workspace_assets), Ok(()));
        assert!(
            validate_assets(&[asset(
                "large-workspace-file",
                MAX_TOTAL_FILE_TEXT_BYTES as u64 + 1,
                InputMaterialization::WorkspaceReadOnly,
            )])
            .is_err()
        );
        let mut too_many = workspace_assets;
        too_many.push(asset(
            "workspace-16",
            1,
            InputMaterialization::WorkspaceReadOnly,
        ));
        assert!(validate_assets(&too_many).is_err());
    }

    #[test]
    fn conversation_provenance_identifiers_use_the_safe_id_domain() {
        let mut fixture = payload();
        fixture.conversation_segments[0].source_run_id = "unsafe run".into();
        fixture.current_user_input.source_run_id = "unsafe run".into();
        assert_eq!(
            validate_conversation(&fixture).unwrap_err().message,
            "bootstrap contains an invalid stable identifier"
        );
    }

    #[test]
    fn disabled_mode_preserves_ordinary_clients() {
        let mut admission = PlantcoreAdmission::disabled();
        assert!(!admission.is_enabled());
        assert_eq!(
            admission.admit_input(&Op::UserInput { text: "hi".into() }),
            Ok(())
        );
        assert!(PlantcoreAdmission::required("https://provider.example/".into()).is_enabled());
    }

    #[test]
    fn bootstrap_replay_is_idempotent_and_conflicting_digest_is_rejected() {
        let prior = PlantcoreBootstrapAccepted {
            run_id: "run-1".into(),
            payload_digest_sha256: "a".repeat(64),
        };
        assert_eq!(replay_admission(&prior, &prior), Ok(prior.clone()));
        let conflict = PlantcoreBootstrapAccepted {
            run_id: "run-1".into(),
            payload_digest_sha256: "b".repeat(64),
        };
        assert_eq!(
            replay_admission(&prior, &conflict).unwrap_err().code,
            "bootstrap_conflict"
        );
    }

    #[test]
    fn limits_enforce_policy_and_calculator_constraints() {
        let mut bad_digest = payload();
        bad_digest.limits.limits_digest_sha256 = HexSha256::digest(b"wrong");
        assert!(validate_limits(&bad_digest).is_err());

        let mut missing_policy = payload();
        missing_policy.limits.max_usd_micros = Some(1);
        missing_policy.limits.limits_digest_sha256 =
            HexSha256::digest(&encode_limits_without_digest(&missing_policy.limits));
        assert_eq!(
            validate_limits(&missing_policy).unwrap_err().message,
            "a USD ceiling requires a complete metering policy"
        );

        let mut unknown_calculator = payload();
        unknown_calculator.limits.max_usd_micros = Some(1);
        unknown_calculator.limits.metering_policy_version = Some("meter-v1".into());
        unknown_calculator.limits.limits_digest_sha256 =
            HexSha256::digest(&encode_limits_without_digest(&unknown_calculator.limits));
        unknown_calculator.metering_policy = Some(iteron_protocol::MeteringPolicySnapshot {
            version: "meter-v1".into(),
            provider: "plantcore".into(),
            model: "qwen".into(),
            effective_from_unix_ms: 1,
            effective_until_unix_ms: 2,
            calculator_contract_version: "future-calculator".into(),
            metering_unit: NATIVE_METERING_UNIT.into(),
            policy_digest_sha256: HexSha256::digest(b"meter"),
            five_class_ceil_v1: iteron_protocol::FiveClassCeilPolicyV1 {
                input_units_per_million: 1,
                output_units_per_million: 1,
                cache_creation_units_per_million: 1,
                cache_read_units_per_million: 1,
                thinking_units_per_million: 1,
            },
        });
        assert_eq!(
            validate_limits(&unknown_calculator).unwrap_err().message,
            "metering policy does not match the admitted engine and calculator"
        );

        let mut unbounded_policy = unknown_calculator;
        unbounded_policy.limits.max_usd_micros = None;
        unbounded_policy.limits.metering_policy_version = None;
        unbounded_policy.limits.limits_digest_sha256 =
            HexSha256::digest(&encode_limits_without_digest(&unbounded_policy.limits));
        let policy = unbounded_policy.metering_policy.as_mut().unwrap();
        policy.effective_from_unix_ms = 0;
        policy.effective_until_unix_ms = i64::MAX;
        policy.calculator_contract_version = FIVE_CLASS_CALCULATOR_VERSION.into();
        policy.policy_digest_sha256 = HexSha256::digest(&encode_metering_without_digest(policy));
        assert_eq!(validate_limits(&unbounded_policy), Ok(()));
    }

    #[test]
    fn artifact_policy_rejects_bad_digest_and_out_of_range_quota() {
        let mut fixture = payload();
        assert_eq!(validate_artifact_policy(&fixture.artifact_policy), Ok(()));

        fixture.artifact_policy.policy_digest_sha256 = HexSha256::digest(b"wrong");
        assert_eq!(
            validate_artifact_policy(&fixture.artifact_policy)
                .unwrap_err()
                .message,
            "artifact policy digest does not match"
        );

        fixture.artifact_policy.max_artifact_count = 0;
        fixture.artifact_policy.policy_digest_sha256 = HexSha256::digest(
            &encode_artifact_policy_without_digest(&fixture.artifact_policy),
        );
        assert_eq!(
            validate_artifact_policy(&fixture.artifact_policy)
                .unwrap_err()
                .message,
            "artifact policy is outside the admitted G1 bounds"
        );
    }

    #[test]
    fn history_keeps_text_roles_without_turning_typed_facts_into_user_prose() {
        let mut fixture = payload();
        fixture.conversation_segments.insert(
            0,
            iteron_protocol::ConversationSegment {
                sequence: 0,
                source_run_id: "source-run".into(),
                fact_digest_sha256: HexSha256::digest(b"answer-fact"),
                fact: ConversationFact::QuestionAnswer {
                    question_id: "question-1".into(),
                    question_digest_sha256: HexSha256::digest(b"question"),
                    answer_utf8: "typed answer".into(),
                    answer_sha256: HexSha256::digest(b"typed answer"),
                    answered_by_actor_id: "actor-1".into(),
                    answered_at_unix_ms: 1,
                },
            },
        );
        let history = history_messages(&fixture).unwrap();
        assert_eq!(history.len(), 1);
        let [Block::Text { text }] = history[0].content.as_slice() else {
            panic!("typed continuation must be one model-visible structured block")
        };
        let projected: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(projected["contract"], "plantcore.conversation-segment.v1");
        assert_eq!(projected["segment"]["source_run_id"], "source-run");
        assert_eq!(projected["segment"]["fact"]["kind"], "question_answer");
        assert_eq!(projected["segment"]["fact"]["answer_utf8"], "typed answer");
    }

    #[test]
    fn initial_input_and_fixed_workspace_must_match_bootstrap_exactly() {
        let mut fixture = payload();
        assert_eq!(
            validate_initial_input(
                &fixture,
                &Op::UserInput {
                    text: "other".into()
                }
            )
            .unwrap_err()
            .code,
            "input_invalid"
        );
        assert_eq!(validate_workspace(&fixture), Ok(()));
        fixture.workspace.work = "/workspace".into();
        assert_eq!(
            validate_workspace(&fixture).unwrap_err().code,
            "bootstrap_invalid"
        );

        let mut mismatched_gateway_posture = payload();
        mismatched_gateway_posture.run_gateway.external_mcp_posture =
            ExternalMcpPosture::RunGateway;
        assert!(
            validate_payload(&mismatched_gateway_posture, "https://provider.example/v1").is_err()
        );
    }

    #[test]
    fn workspace_read_only_assets_are_pre_materialized_not_submission_attachments() {
        let mut fixture = payload();
        fixture.input_assets = (0..16)
            .map(|index| InputAssetRef {
                asset_handle: format!("workspace-{index}"),
                relative_path: format!("workspace-{index}.txt"),
                media_type: "text/plain".into(),
                size_bytes: 1,
                content_sha256: HexSha256::digest(b"x"),
                materialization: InputMaterialization::WorkspaceReadOnly,
            })
            .collect();

        assert_eq!(validate_assets(&fixture.input_assets), Ok(()));
        assert_eq!(
            validate_initial_input(
                &fixture,
                &Op::UserInput {
                    text: "hello".into()
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn metering_digest_matches_generated_protobuf_default_omission() {
        let policy = iteron_protocol::MeteringPolicySnapshot {
            version: "recording-v1".into(),
            provider: "plantcore-recording".into(),
            model: "fixture-model".into(),
            effective_from_unix_ms: 0,
            effective_until_unix_ms: 9_007_199_254_740_991,
            calculator_contract_version: FIVE_CLASS_CALCULATOR_VERSION.into(),
            metering_unit: NATIVE_METERING_UNIT.into(),
            policy_digest_sha256: HexSha256::digest(b"cleared for digest"),
            five_class_ceil_v1: iteron_protocol::FiveClassCeilPolicyV1 {
                input_units_per_million: 1_000_000,
                output_units_per_million: 2_000_000,
                cache_creation_units_per_million: 3_000_000,
                cache_read_units_per_million: 0,
                thinking_units_per_million: 2_000_000,
            },
        };
        let encoded = encode_metering_without_digest(&policy);
        assert_eq!(
            hex::encode(&encoded),
            concat!(
                "0a0c7265636f7264696e672d76311213706c616e74636f72652d7265636f7264696e67",
                "1a0d666978747572652d6d6f64656c28ffffffffffffff0f3225706c616e74636f7265",
                "2e6d65746572696e672e666976652d636c6173732d6365696c2e76313a095553445f4d",
                "4943524fa2011108c0843d1080897a18c08db7012880897a"
            )
        );
        assert_eq!(
            HexSha256::digest(&encoded).to_lower_hex(),
            "d8aaa42dc39d68ff39d69bfccc2ec1433bc8536486a5713a6f33cea2bccfec56"
        );
    }

    #[test]
    fn protobuf_encoder_uses_two_complement_int64_varints() {
        let mut encoded = Vec::new();
        field_varint(&mut encoded, 1, (-1_i64) as u64);
        assert_eq!(encoded.len(), 11);
        assert_eq!(encoded[0], 8);
        assert_eq!(*encoded.last().unwrap(), 1);
    }

    #[test]
    fn published_app_server_examples_match_the_draft_2020_12_contract() {
        let validator = app_server_schema();
        for bytes in [
            include_bytes!("../../../../contracts/plantcore/examples/app-server-v4-listening.json")
                .as_slice(),
            include_bytes!("../../../../contracts/plantcore/examples/app-server-v4-bootstrap.json")
                .as_slice(),
            include_bytes!(
                "../../../../contracts/plantcore/examples/app-server-v4-bootstrap-reply.json"
            )
            .as_slice(),
            include_bytes!("../../../../contracts/plantcore/examples/app-server-v4-command.json")
                .as_slice(),
            include_bytes!(
                "../../../../contracts/plantcore/examples/app-server-v4-command-reply.json"
            )
            .as_slice(),
            include_bytes!(
                "../../../../contracts/plantcore/examples/app-server-v4-pause-command.json"
            )
            .as_slice(),
            include_bytes!(
                "../../../../contracts/plantcore/examples/app-server-v4-pause-command-reply.json"
            )
            .as_slice(),
            include_bytes!(
                "../../../../contracts/plantcore/examples/app-server-v4-resume-command.json"
            )
            .as_slice(),
            include_bytes!(
                "../../../../contracts/plantcore/examples/app-server-v4-resume-command-reply.json"
            )
            .as_slice(),
            include_bytes!(
                "../../../../contracts/plantcore/examples/app-server-v4-resume-terminal-command.json"
            )
            .as_slice(),
            include_bytes!(
                "../../../../contracts/plantcore/examples/app-server-v4-resume-terminal-command-reply.json"
            )
            .as_slice(),
        ] {
            let value = serde_json::from_slice(bytes).unwrap();
            if let Err(error) = validator.validate(&value) {
                panic!("published App Server example violates its schema: {error}");
            }
        }
        let invalid_bootstrap = serde_json::from_slice(include_bytes!(
            "../../../../contracts/plantcore/examples/app-server-v4-invalid-bootstrap.json"
        ))
        .unwrap();
        assert!(validator.validate(&invalid_bootstrap).is_err());

        // A mismatched resume session is structurally valid and is rejected against live process
        // state by the protocol implementation, not by the release's frame-shape schema.
        let invalid_session = serde_json::from_slice(include_bytes!(
            "../../../../contracts/plantcore/examples/app-server-v4-invalid-session.json"
        ))
        .unwrap();
        assert!(validator.validate(&invalid_session).is_ok());

        for reason in [
            "dispatch_resume_pending",
            "recording_pause_checkpoint_failed",
            "recording_pause_checkpoint_invalid",
            "dispatch_resume_generation_exhausted",
        ] {
            let reply = serde_json::json!({
                "type": "control_reply",
                "protocol_version": 4,
                "request_id": 11,
                "reply": {
                    "type": "plantcore_command_reply_v1",
                    "command_id": "command-rejected-0001",
                    "status": "rejected",
                    "reason": reason,
                },
            });
            if let Err(error) = validator.validate(&reply) {
                panic!("published command rejection violates the App Server schema: {error}");
            }
        }
    }
}
