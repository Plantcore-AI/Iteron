//! Typed production-owner facts for tunable families 1 through 34.
//!
//! This adapter deliberately keeps value projection separate from constraint projection. Both
//! are rebuilt from typed owner state; a candidate [`ResolutionValue`] is never recycled as the
//! evidence that authorizes itself. Schema/owner mismatches remain explicit [`CoreFactGap`]s.

#[path = "core_facts/constraints.rs"]
mod constraints;
#[path = "core_facts/value.rs"]
mod value;

use constraints::add_constraints;
use value::*;

use crate::config::ConfigOrigin;
use crate::providers::{ModelCapabilities, ModelSelection};
use iteron_ctx::{CompactionPolicy, MemBudget};
use iteron_protocol::permission::{PermissionMode, PermissionRules, Verdict};
use iteron_protocol::{Budget, Effort};
use iteron_sched::BackoffPolicy;
use iteron_tunables::{
    CapabilityRequirement, ConstraintValue, DecimalValue, ExternalCeiling, ResolutionValue,
    RouteCapabilities, RuntimeResolutionBuilder, RuntimeResolutionError, SourceKind,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

const RATIO_EIGHT_TENTHS: DecimalValue = DecimalValue {
    coefficient: 8,
    scale: 1,
};
const SUMMARY_OUTPUT_TOKENS: i64 = 2_048;
const INSTRUCTION_MAX_DEPTH: i64 = 8;
const INSTRUCTION_MAX_FILES: i64 = 64;
const INSTRUCTION_PER_FILE_BYTES: i64 = 8_000;
const INSTRUCTION_TOTAL_BYTES: i64 = 32_768;
const MEMORY_FACT_BYTES: i64 = 8_000;
const SKILL_LISTING_BYTES: i64 = 2_000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Sourced<T> {
    pub value: T,
    pub origin: ConfigOrigin,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BudgetOrigins {
    pub max_turns: ConfigOrigin,
    pub max_usd: Option<ConfigOrigin>,
    pub max_tokens: Option<ConfigOrigin>,
    pub max_wall_secs: ConfigOrigin,
    pub max_consecutive_tool_errors: ConfigOrigin,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RetryOrigins {
    pub base_ms: ConfigOrigin,
    pub cap_ms: ConfigOrigin,
    pub max_attempts: ConfigOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompactionOwner {
    AdaptiveDefault,
    UserFixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromptCacheOwner {
    Builtin,
    RustBuilder,
}

pub(crate) struct CoreFactsInput<'a> {
    pub selection: &'a ModelSelection,
    pub provider_origin: ConfigOrigin,
    pub model_origin: ConfigOrigin,
    pub base_url: Sourced<&'a str>,
    pub effort: Sourced<Effort>,
    pub budget: &'a Budget,
    pub budget_origins: BudgetOrigins,
    pub allow_code: Sourced<bool>,
    pub permission_mode: Sourced<PermissionMode>,
    /// `None` means the owner returned its empty derived default; the only declared source is
    /// `Some(UserConfig)`.
    pub permission_rules_origin: Option<ConfigOrigin>,
    pub permission_rules: &'a PermissionRules,
    pub bypass_permissions: Sourced<bool>,
    /// Trusted operator grant. `None` preserves the explicit legacy/unconfined posture; an empty
    /// configured list is a real deny-all policy.
    pub operator_egress_allow: Option<&'a [String]>,
    /// Repository input can only intersect the operator grant. With no operator grant its base is
    /// empty, so repository configuration can never mint a destination.
    pub project_egress_allow: Option<&'a [String]>,
    pub compaction: &'a CompactionPolicy,
    pub compaction_owner: CompactionOwner,
    pub retry: &'a BackoffPolicy,
    pub retry_origins: RetryOrigins,
    pub verify_command: Option<&'a str>,
    /// The verifier's independently materialized command, not the CLI candidate.
    pub verifier_plan_command: Option<&'a str>,
    pub memory_enabled: bool,
    /// Independent tenant policy. `true` admits both enabled and disabled; `false` admits only
    /// disabled memory.
    pub tenant_allows_memory: bool,
    pub model_capabilities: &'a ModelCapabilities,
    pub route: &'a RouteCapabilities,
    pub prompt_cache_enabled: bool,
    pub prompt_cache_owner: PromptCacheOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoreFactGap {
    ParentTokenCeilingAbsent,
    ParentTokenCeilingBelowThinkingMap,
    ContextByteCeilingNotOwned,
    ContextMessageCeilingNotOwned,
    MemoryInstructionBudgetNotRepresentable,
    PromptCacheCapabilityUnattested,
    ContextWindowUnknown,
    VerificationPlanAbsent,
}

#[derive(Debug, Default)]
pub(crate) struct CoreFactsReport {
    pub gaps: Vec<CoreFactGap>,
    pub unavailable_families: Vec<&'static str>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CoreFactError {
    #[error("selected provider/model does not match the admitted route attestation")]
    RouteIdentityMismatch,
    #[error("max_usd cannot be represented exactly enough at the registry's six-decimal scale")]
    MonetaryScaleLoss,
    #[error("runtime owner value for `{0}` exceeds the registry integer representation")]
    IntegerOverflow(&'static str),
    #[error("permission rule key is outside the bounded namespaced-id schema")]
    InvalidPermissionRuleKey,
    #[error("iteron owner evidence could not be encoded")]
    EvidenceEncoding,
    #[error(transparent)]
    Resolution(#[from] RuntimeResolutionError),
}

/// Add every honestly representable fact for families 1..=34. Gaps are returned, not silently
/// replaced with guessed values.
pub(crate) fn apply_core_facts(
    builder: &mut RuntimeResolutionBuilder,
    input: CoreFactsInput<'_>,
) -> Result<CoreFactsReport, CoreFactError> {
    verify_route(&input)?;
    input
        .budget
        .validate()
        .map_err(|_| CoreFactError::MonetaryScaleLoss)?;
    let mut report = CoreFactsReport::default();

    declare(
        builder,
        "provider",
        input.provider_origin,
        en(&input.selection.provider_id),
    )?;
    declare(
        builder,
        "model",
        input.model_origin,
        en(&input.selection.model_id),
    )?;
    if input.base_url.origin == ConfigOrigin::Builtin {
        builder.observe_default("base_url", text(input.base_url.value))?;
    } else {
        declare(
            builder,
            "base_url",
            input.base_url.origin,
            text(input.base_url.value),
        )?;
    }
    if input.effort.origin != ConfigOrigin::Builtin || input.effort.value != Effort::Medium {
        declare(
            builder,
            "effort",
            input.effort.origin,
            en(input.effort.value.label()),
        )?;
    }
    add_budget_values(builder, &input)?;
    declare(
        builder,
        "allow_code",
        input.allow_code.origin,
        boolv(input.allow_code.value),
    )?;
    declare(
        builder,
        "permission_mode",
        input.permission_mode.origin,
        en(input.permission_mode.value.label()),
    )?;
    add_permission_rules(builder, &input)?;
    declare(
        builder,
        "bypass_permissions",
        input.bypass_permissions.origin,
        boolv(input.bypass_permissions.value),
    )?;
    if let Some(destinations) = input.operator_egress_allow {
        builder.declare(
            "egress_allow",
            SourceKind::UserConfig,
            text_list(destinations),
        )?;
    }
    if let Some(destinations) = input.project_egress_allow {
        builder.declare(
            "egress_allow",
            SourceKind::ProjectConfig,
            text_list(destinations),
        )?;
    }
    add_compaction(builder, &input)?;
    add_retry_and_verify(builder, &input)?;
    add_internal_defaults(builder, &input, &mut report)?;
    add_constraints(builder, &input, &mut report)?;
    activate_core_seams(builder, &input)?;
    Ok(report)
}

fn add_budget_values(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
) -> Result<(), CoreFactError> {
    let b = input.budget;
    declare(
        builder,
        "max_turns",
        input.budget_origins.max_turns,
        int(b.max_turns.into()),
    )?;
    if let (Some(value), Some(origin)) = (b.max_usd, input.budget_origins.max_usd) {
        declare(builder, "max_usd", origin, money(value)?)?;
    }
    if let (Some(value), Some(origin)) = (b.max_tokens, input.budget_origins.max_tokens) {
        declare(
            builder,
            "max_tokens",
            origin,
            int(i64v(value, "max_tokens")?),
        )?;
    }
    declare(
        builder,
        "max_wall_secs",
        input.budget_origins.max_wall_secs,
        int(i64v(b.max_wall_secs, "max_wall_secs")?),
    )?;
    declare(
        builder,
        "max_consecutive_tool_errors",
        input.budget_origins.max_consecutive_tool_errors,
        int(b.max_consecutive_tool_errors.into()),
    )?;
    Ok(())
}

fn add_permission_rules(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
) -> Result<(), CoreFactError> {
    match input.permission_rules_origin {
        Some(origin) => declare(
            builder,
            "permission_rules",
            origin,
            rules(input.permission_rules)?,
        )?,
        None => {
            builder.observe_default("permission_rules", rules(input.permission_rules)?)?;
        }
    };
    Ok(())
}

fn add_compaction(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
) -> Result<(), CoreFactError> {
    let reserve = i64::from(input.model_capabilities.max_output_tokens.unwrap_or(8_192));
    let trigger = object([
        (
            "mode",
            en(
                if input.compaction_owner == CompactionOwner::AdaptiveDefault {
                    "adaptive"
                } else {
                    "fixed"
                },
            ),
        ),
        ("usable_window_ratio", dec(RATIO_EIGHT_TENTHS)),
        (
            "fallback_trigger_tokens",
            int(i64u(input.compaction.trigger_tokens, "compaction_trigger")?),
        ),
        ("output_reserve_tokens", int(reserve)),
    ]);
    if input.compaction_owner == CompactionOwner::AdaptiveDefault {
        builder.observe_default("compaction_trigger", trigger)?;
    } else {
        builder.declare("compaction_trigger", SourceKind::UserConfig, trigger)?;
    }
    builder.observe_default(
        "compaction_adaptive",
        object([
            ("usable_window_ratio", dec(RATIO_EIGHT_TENTHS)),
            (
                "keep_recent_messages",
                int(i64u(input.compaction.keep_recent, "keep_recent")?),
            ),
            ("output_reserve_tokens", int(reserve)),
        ]),
    )?;
    builder.observe_default(
        "compaction_keep_recent",
        int(i64u(input.compaction.keep_recent, "keep_recent")?),
    )?;
    Ok(())
}

fn add_retry_and_verify(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
) -> Result<(), CoreFactError> {
    declare(
        builder,
        "retry_backoff_base",
        input.retry_origins.base_ms,
        int(i64v(input.retry.base_ms, "retry_base")?),
    )?;
    declare(
        builder,
        "retry_backoff_cap",
        input.retry_origins.cap_ms,
        int(i64v(input.retry.cap_ms, "retry_cap")?),
    )?;
    declare(
        builder,
        "retry_max_attempts",
        input.retry_origins.max_attempts,
        int(input.retry.max_attempts.into()),
    )?;
    if let Some(command) = input.verify_command {
        builder.declare("verify_command", SourceKind::Cli, text(command))?;
    }
    Ok(())
}

fn add_internal_defaults(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
    report: &mut CoreFactsReport,
) -> Result<(), CoreFactError> {
    match input.model_capabilities.max_output_tokens {
        Some(cap) => builder.observe_default("request_output_cap", int(cap.into()))?,
        None => builder.observe_default_absent("request_output_cap", "model_max_output_unknown")?,
    };
    if input
        .route
        .capabilities
        .contains(&CapabilityRequirement::ProviderReasoningControl)
    {
        builder.observe_default("effort_reasoning_map", effort_reasoning_map())?;
        builder.observe_default("thinking_map", thinking_map())?;
    } else {
        // These maps are meaningful only when the exact provider/model route attests a semantic
        // reasoning control. Publishing the six built-in labels against an observed-empty
        // provider-reasoning catalog both violates the catalog schema and, worse, implies that a
        // route accepts controls it never advertised. Keep the families honestly inactive.
        builder.observe_default_absent(
            "effort_reasoning_map",
            "provider_reasoning_control_not_attested",
        )?;
        builder
            .observe_default_absent("thinking_map", "provider_reasoning_control_not_attested")?;
    }
    builder.observe_default("orchestration_map", orchestration_map())?;
    if input
        .route
        .capabilities
        .contains(&CapabilityRequirement::ProviderPromptCache)
    {
        builder.declare(
            "prompt_cache",
            match input.prompt_cache_owner {
                PromptCacheOwner::Builtin => SourceKind::Builtin,
                PromptCacheOwner::RustBuilder => SourceKind::RustBuilder,
            },
            boolv(input.prompt_cache_enabled),
        )?;
    }
    // The estimator id names the actual route-selected conservative algorithm. It remains an
    // explicitly inexact approximation and provider usage is reconciled after the response.
    let estimator = iteron_ctx::TokenEstimatorProfile::for_route(
        Some(&input.selection.provider_id),
        &input.selection.model_id,
    )
    .identity();
    builder.observe_default(
        "token_estimator",
        object([
            ("estimator", en(&estimator.catalog_id)),
            (
                "safety_margin",
                dec(DecimalValue {
                    coefficient: 0,
                    scale: 0,
                }),
            ),
        ]),
    )?;
    builder.observe_default(
        "summary_profile",
        object([
            ("max_output_tokens", int(SUMMARY_OUTPUT_TOKENS)),
            ("effort", en("low")),
            ("preserve_tool_evidence", boolv(true)),
        ]),
    )?;
    builder.observe_default("compaction_failure", en("retain_original"))?;
    builder.observe_default(
        "instruction_discovery_render",
        object([
            ("max_depth", int(INSTRUCTION_MAX_DEPTH)),
            ("max_files", int(INSTRUCTION_MAX_FILES)),
            ("per_file_bytes", int(INSTRUCTION_PER_FILE_BYTES)),
            ("total_bytes", int(INSTRUCTION_TOTAL_BYTES)),
        ]),
    )?;
    builder.declare(
        "memory_enable",
        SourceKind::Builtin,
        boolv(input.memory_enabled),
    )?;
    add_memory_defaults(builder, report)?;
    Ok(())
}

fn add_memory_defaults(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut CoreFactsReport,
) -> Result<(), CoreFactError> {
    let mem = MemBudget::default();
    builder.observe_default(
        "memory_budgets",
        object([
            (
                "recall_bytes",
                int(i64u(mem.recall_bytes, "memory_recall")?),
            ),
            ("index_bytes", int(i64u(mem.index_bytes, "memory_index")?)),
            (
                "instruction_bytes",
                int(i64u(mem.instr_bytes, "memory_instructions")?),
            ),
            ("fact_bytes", int(MEMORY_FACT_BYTES)),
            ("total_bytes", int(i64u(mem.total, "memory_total")?)),
        ]),
    )?;
    builder.observe_default(
        "bm25",
        map([
            (
                "k1",
                dec(DecimalValue {
                    coefficient: 12,
                    scale: 1,
                }),
            ),
            (
                "b",
                dec(DecimalValue {
                    coefficient: 75,
                    scale: 2,
                }),
            ),
            (
                "recall_limit",
                dec(DecimalValue {
                    coefficient: 32,
                    scale: 0,
                }),
            ),
        ]),
    )?;
    builder.observe_default("skill_listing_budget", int(SKILL_LISTING_BYTES))?;
    Ok(())
}
