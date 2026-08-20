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
    CapabilityRequirement, ConstraintValue, DecimalValue, ExternalCeiling, FixedAuthorityId,
    ProductionOwnerSymbolId, ResolutionValue, RouteCapabilities, RuntimeResolutionBuilder,
    RuntimeResolutionError, SourceKind,
};
use std::collections::BTreeMap;

use super::fixed_artifacts::FixedAuthoritySample;

fn usable_window_ratio() -> DecimalValue {
    DecimalValue {
        coefficient: 82,
        scale: 2,
    }
}
const SUMMARY_OUTPUT_TOKENS: i64 = 2_048;
const MEMORY_FACT_BYTES: i64 = 8_000;
const SKILL_LISTING_BYTES: i64 = 2_000;
/// Canonical family-19 resolver fallback when selected-route metadata cannot attest an output
/// ceiling. Every context/compaction fact collector must use this same execution value.
pub(crate) const UNKNOWN_MODEL_OUTPUT_TOKENS: u32 = 8_192;
/// Stand-in aggregate parent-token budget when the run declares none. An absent budget is
/// unbounded authority, so the clamp must not shrink the attested output cap below this.
const ABSENT_PARENT_TOKEN_CEILING: u64 = 1_000_000;

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
#[allow(
    dead_code,
    reason = "the closed prompt-cache owner vocabulary preserves literal-owner drift refusal"
)]
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
    pub memory_enabled: Sourced<bool>,
    /// Independent tenant policy. `true` admits both enabled and disabled; `false` admits only
    /// disabled memory.
    pub tenant_allows_memory: bool,
    pub model_capabilities: &'a ModelCapabilities,
    pub route: &'a RouteCapabilities,
    pub prompt_cache_enabled: bool,
    pub prompt_cache_owner: PromptCacheOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "typed owner-gap categories remain explicit for fail-closed composition audits"
)]
pub(crate) enum CoreFactGap {
    ParentTokenCeilingAbsent,
    ParentTokenCeilingBelowThinkingMap,
    MemoryInstructionBudgetNotRepresentable,
    ContextWindowUnknown,
    VerificationPlanAbsent,
}

#[derive(Debug, Default)]
pub(crate) struct CoreFactsReport {
    pub gaps: Vec<CoreFactGap>,
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

    literal_with_override(
        builder,
        "provider",
        en("glm"),
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
    literal_with_override(
        builder,
        "effort",
        en("medium"),
        input.effort.origin,
        en(input.effort.value.label()),
    )?;
    add_budget_values(builder, &input)?;
    literal_with_override(
        builder,
        "allow_code",
        boolv(true),
        input.allow_code.origin,
        boolv(input.allow_code.value),
    )?;
    literal_with_override(
        builder,
        "permission_mode",
        en("default"),
        input.permission_mode.origin,
        en(input.permission_mode.value.label()),
    )?;
    add_permission_rules(builder, &input)?;
    literal_with_override(
        builder,
        "bypass_permissions",
        boolv(true),
        input.bypass_permissions.origin,
        boolv(input.bypass_permissions.value),
    )?;
    // The empty literal is the executable egress owner's baseline. Operator/repository allowlists
    // are separate authorized declarations and cannot stand in for sampling that fixed owner.
    builder.attest_literal_owner("egress_allow", text_list(&[]))?;
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
    submit_owner_symbols(builder)?;
    Ok(report)
}

/// Re-sample only fixed core owners that are immutable properties of this binary. Values derived
/// from a run's route, context window, or budget are deliberately excluded and reconstructed from
/// the immutable V2 checkpoint by their production decoders instead.
pub(crate) fn live_fixed_authority_samples() -> Vec<FixedAuthoritySample> {
    vec![
        FixedAuthoritySample {
            family: "effort_reasoning_map",
            authority: FixedAuthorityId::StrategyInvariant,
            value: effort_reasoning_map(),
        },
        FixedAuthoritySample {
            family: "thinking_map",
            authority: FixedAuthorityId::StrategyInvariant,
            value: thinking_map(),
        },
        FixedAuthoritySample {
            family: "orchestration_map",
            authority: FixedAuthorityId::StrategyInvariant,
            value: orchestration_map(),
        },
        FixedAuthoritySample {
            family: "compaction_failure",
            authority: FixedAuthorityId::StrategyInvariant,
            value: compaction_failure_owner_value(),
        },
    ]
}

fn submit_owner_symbols(builder: &mut RuntimeResolutionBuilder) -> Result<(), CoreFactError> {
    use ProductionOwnerSymbolId as Owner;
    for (owner, families) in [
        (
            Owner::ProviderSelection,
            &["provider", "model", "base_url"][..],
        ),
        (Owner::EffortPolicy, &["effort"][..]),
        (
            Owner::BudgetPolicy,
            &["max_turns", "max_usd", "max_tokens", "max_wall_secs"][..],
        ),
        (
            Owner::PermissionPolicy,
            &[
                "allow_code",
                "permission_mode",
                "permission_rules",
                "bypass_permissions",
            ][..],
        ),
        (
            Owner::CompactionPolicy,
            &["compaction_trigger", "summary_profile"][..],
        ),
        (Owner::VerificationPolicy, &["verify_command"][..]),
        (
            Owner::RetryPolicy,
            &[
                "retry_backoff_base",
                "retry_backoff_cap",
                "retry_max_attempts",
            ][..],
        ),
        (Owner::EgressPolicy, &["egress_allow"][..]),
        (Owner::ProviderInstance, &["prompt_cache"][..]),
        (
            Owner::InstructionDiscoveryPolicy,
            &["instruction_discovery_render"][..],
        ),
        (
            Owner::MemoryPolicy,
            &["memory_enable", "memory_budgets"][..],
        ),
    ] {
        builder.submit_owner_symbol(owner, families)?;
    }
    Ok(())
}

fn add_budget_values(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
) -> Result<(), CoreFactError> {
    let b = input.budget;
    literal_with_override(
        builder,
        "max_turns",
        int(64),
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
    literal_with_override(
        builder,
        "max_wall_secs",
        int(3_600),
        input.budget_origins.max_wall_secs,
        int(i64v(b.max_wall_secs, "max_wall_secs")?),
    )?;
    let max_consecutive_tool_errors = int(b.max_consecutive_tool_errors.into());
    declare(
        builder,
        "max_consecutive_tool_errors",
        input.budget_origins.max_consecutive_tool_errors,
        max_consecutive_tool_errors.clone(),
    )?;
    builder.attest_fixed_authority(
        "max_consecutive_tool_errors",
        FixedAuthorityId::StrategyInvariant,
        max_consecutive_tool_errors,
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
    let reserve = model_output_reserve(input);
    let context_ceiling = compaction_context_ceiling(input);
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
        ("usable_window_ratio", dec(usable_window_ratio())),
        (
            "fallback_trigger_tokens",
            int(i64u(input.compaction.trigger_tokens, "compaction_trigger")?),
        ),
        (
            "output_reserve_tokens",
            int(i64v(reserve, "compaction_trigger")?),
        ),
    ]);
    if input.compaction_owner == CompactionOwner::AdaptiveDefault {
        builder.observe_default("compaction_trigger", trigger)?;
    } else {
        builder.declare("compaction_trigger", SourceKind::UserConfig, trigger)?;
    }
    let compaction_adaptive = object([
        ("usable_window_ratio", dec(usable_window_ratio())),
        (
            "keep_recent_messages",
            int(i64u(input.compaction.keep_recent, "keep_recent")?),
        ),
        (
            "output_reserve_tokens",
            int(i64v(reserve.min(context_ceiling), "compaction_adaptive")?),
        ),
    ]);
    // The fixed receipt binds the post-ceiling value which the checkpoint decoder executes. The
    // default evidence above remains the independent pre-constraint owner observation.
    builder.observe_default(
        "compaction_adaptive",
        object([
            ("usable_window_ratio", dec(usable_window_ratio())),
            (
                "keep_recent_messages",
                int(i64u(input.compaction.keep_recent, "keep_recent")?),
            ),
            (
                "output_reserve_tokens",
                int(i64v(reserve, "compaction_adaptive")?),
            ),
        ]),
    )?;
    builder.attest_fixed_authority(
        "compaction_adaptive",
        FixedAuthorityId::StrategyInvariant,
        compaction_adaptive,
    )?;
    let keep_recent = i64u(input.compaction.keep_recent, "keep_recent")?;
    builder.observe_default("compaction_keep_recent", int(keep_recent))?;
    builder.attest_fixed_authority(
        "compaction_keep_recent",
        FixedAuthorityId::StrategyInvariant,
        int(keep_recent.min(i64v(context_ceiling, "compaction_keep_recent")?)),
    )?;
    Ok(())
}

fn add_retry_and_verify(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
) -> Result<(), CoreFactError> {
    literal_with_override(
        builder,
        "retry_backoff_base",
        int(500),
        input.retry_origins.base_ms,
        int(i64v(input.retry.base_ms, "retry_base")?),
    )?;
    literal_with_override(
        builder,
        "retry_backoff_cap",
        int(30_000),
        input.retry_origins.cap_ms,
        int(i64v(input.retry.cap_ms, "retry_cap")?),
    )?;
    literal_with_override(
        builder,
        "retry_max_attempts",
        int(3),
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
    // The canonical model-default contract supplies the conservative execution cap when fresh
    // metadata cannot attest a narrower provider maximum. This value is pinned into the
    // checkpoint and remains the request value on resume; later provider metadata is only an
    // upper-ceiling check and never silently replaces it.
    let output_reserve = model_output_reserve(input);
    builder.observe_default(
        "request_output_cap",
        int(i64v(output_reserve, "request_output_cap")?),
    )?;
    if input
        .route
        .capabilities
        .contains(&CapabilityRequirement::ProviderModelMetadata)
    {
        builder.attest_fixed_authority(
            "request_output_cap",
            FixedAuthorityId::StrategyInvariant,
            int(i64v(
                output_reserve.min(input.budget.max_tokens.unwrap_or(
                    iteron_tunables::param_integer(
                        "cli.runtime_tunables.core_facts.absent_parent_token_ceiling",
                        ABSENT_PARENT_TOKEN_CEILING,
                    ),
                )),
                "request_output_cap",
            )?),
        )?;
    }
    if input
        .route
        .capabilities
        .contains(&CapabilityRequirement::ProviderReasoningControl)
    {
        let reasoning = effort_reasoning_map();
        builder.observe_default("effort_reasoning_map", reasoning.clone())?;
        builder.attest_fixed_authority(
            "effort_reasoning_map",
            FixedAuthorityId::StrategyInvariant,
            reasoning,
        )?;
        let thinking = thinking_map();
        builder.observe_default("thinking_map", thinking.clone())?;
        if input
            .budget
            .max_tokens
            .is_none_or(|tokens| tokens >= u64::from(Effort::Ultracode.thinking_budget()))
        {
            builder.attest_fixed_authority(
                "thinking_map",
                FixedAuthorityId::StrategyInvariant,
                thinking,
            )?;
        }
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
    let orchestration = orchestration_map();
    builder.observe_default("orchestration_map", orchestration.clone())?;
    builder.attest_fixed_authority(
        "orchestration_map",
        FixedAuthorityId::StrategyInvariant,
        orchestration,
    )?;
    let provider_supports_prompt_cache = input
        .route
        .capabilities
        .contains(&CapabilityRequirement::ProviderPromptCache);
    // Family 23 is an always-active outer gate. A route that cannot attest cache support owns an
    // exact `false`, not an absent value: absence would leave a Full family unresolved, while
    // retaining the operator's `true` would claim wire authority the adapter cannot honor.
    builder.attest_literal_owner("prompt_cache", boolv(true))?;
    let prompt_cache = boolv(input.prompt_cache_enabled && provider_supports_prompt_cache);
    match input.prompt_cache_owner {
        PromptCacheOwner::Builtin if prompt_cache == boolv(true) => {}
        PromptCacheOwner::Builtin => {
            // Preserve the global invariant: a Builtin declaration may only restate the embedded
            // literal. This call intentionally returns LiteralOwnerMismatch for drift.
            builder.declare("prompt_cache", SourceKind::Builtin, prompt_cache)?;
        }
        PromptCacheOwner::RustBuilder => {
            builder.declare("prompt_cache", SourceKind::RustBuilder, prompt_cache)?;
        }
    }
    // The checkpoint pins the deterministic route-aware selector policy, not one concrete route's
    // profile. Each selected profile is still exposed through ContextLedger's tokenizer identity.
    let token_estimator = object([
        ("estimator", en(iteron_ctx::ROUTE_AWARE_ESTIMATOR_POLICY_ID)),
        (
            "safety_margin",
            dec(DecimalValue {
                coefficient: 0,
                scale: 0,
            }),
        ),
    ]);
    builder.observe_default("token_estimator", token_estimator.clone())?;
    builder.attest_fixed_authority(
        "token_estimator",
        FixedAuthorityId::GovernedArtifactBoundary,
        token_estimator,
    )?;
    builder.observe_default(
        "summary_profile",
        object([
            (
                "max_output_tokens",
                int(iteron_tunables::param_integer(
                    "cli.runtime_tunables.core_facts.summary_output_tokens",
                    SUMMARY_OUTPUT_TOKENS,
                )),
            ),
            ("effort", en("low")),
            ("preserve_tool_evidence", boolv(true)),
        ]),
    )?;
    let compaction_failure = compaction_failure_owner_value();
    builder.observe_default("compaction_failure", compaction_failure.clone())?;
    builder.attest_fixed_authority(
        "compaction_failure",
        FixedAuthorityId::StrategyInvariant,
        compaction_failure,
    )?;
    builder.observe_default(
        "instruction_discovery_render",
        instruction_discovery_value()?,
    )?;
    literal_with_override(
        builder,
        "memory_enable",
        boolv(true),
        input.memory_enabled.origin,
        boolv(input.memory_enabled.value),
    )?;
    add_memory_defaults(builder, report)?;
    Ok(())
}

fn compaction_failure_owner_value() -> ResolutionValue {
    en("retain_original")
}

fn add_memory_defaults(
    builder: &mut RuntimeResolutionBuilder,
    _report: &mut CoreFactsReport,
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
            (
                "fact_bytes",
                int(iteron_tunables::param_integer(
                    "cli.runtime_tunables.core_facts.memory_fact_bytes",
                    MEMORY_FACT_BYTES,
                )),
            ),
            ("total_bytes", int(i64u(mem.total, "memory_total")?)),
        ]),
    )?;
    let bm25 = map([
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
    ]);
    builder.observe_default("bm25", bm25.clone())?;
    builder.attest_fixed_authority("bm25", FixedAuthorityId::StrategyInvariant, bm25)?;
    builder.observe_default(
        "skill_listing_budget",
        int(iteron_tunables::param_integer(
            "cli.runtime_tunables.core_facts.skill_listing_bytes",
            SKILL_LISTING_BYTES,
        )),
    )?;
    builder.attest_fixed_authority(
        "skill_listing_budget",
        FixedAuthorityId::StrategyInvariant,
        int(iteron_tunables::param_integer(
            "cli.runtime_tunables.core_facts.skill_listing_bytes",
            SKILL_LISTING_BYTES,
        )
        .min(i64::from(
            iteron_ctx::ContextMaterializationPolicy::default().max_bytes,
        ))),
    )?;
    Ok(())
}

pub(super) fn model_output_reserve(input: &CoreFactsInput<'_>) -> u64 {
    u64::from(
        input
            .model_capabilities
            .max_output_tokens
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime_tunables.core_facts.unknown_model_output_tokens",
                UNKNOWN_MODEL_OUTPUT_TOKENS,
            )),
    )
}

pub(super) fn compaction_context_ceiling(input: &CoreFactsInput<'_>) -> u64 {
    input
        .model_capabilities
        .context_window_tokens
        .unwrap_or_else(|| {
            u64::try_from(input.compaction.trigger_tokens)
                .unwrap_or(u64::MAX)
                .saturating_add(model_output_reserve(input))
        })
}
