use super::value::{boolv, en, memory_mode, object, replay_policy, session_profile, text};
use super::{
    ExtensionFactError, ExtensionFactsInput, ExtensionFactsReport, ExtensionGapReason, FactLayer,
    GapImpact, McpTransport, OAuthLifecycleMode,
};
use crate::config::McpTransportConfig;
use core_tunables::{RuntimeResolutionBuilder, SourceKind};
use std::collections::BTreeSet;

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    add_child_defaults(builder, input, report)?;

    builder.observe_default(
        "per_session_spawn_cap",
        super::value::int(super::value::i64u(
            input.session_spawn_ledger.limit(),
            "per_session_spawn_cap",
        )?),
    )?;
    report.mark(138, "per_session_spawn_cap", FactLayer::Default);
    builder.declare(
        "early_stop_quorum_policy",
        SourceKind::Builtin,
        object([
            (
                "minimum_evidence",
                super::value::int(super::value::i64u(
                    input.early_stop_quorum.minimum_evidence(),
                    "early_stop_quorum_policy",
                )?),
            ),
            (
                "required_roles",
                super::value::int(super::value::i64u(
                    input.early_stop_quorum.required_roles(),
                    "early_stop_quorum_policy",
                )?),
            ),
            ("strong_veto", boolv(input.early_stop_quorum.strong_veto())),
        ]),
    )?;
    report.mark(142, "early_stop_quorum_policy", FactLayer::Default);
    builder.declare(
        "speculative_sibling_count",
        SourceKind::Builtin,
        super::value::int(super::value::i64u(
            input.speculative_siblings.max_siblings(),
            "speculative_sibling_count",
        )?),
    )?;
    report.mark(140, "speculative_sibling_count", FactLayer::Default);
    builder.observe_default(
        "speculative_sibling_cancellation",
        object([
            (
                "winner_evidence",
                en(input.speculative_siblings.winner_evidence().label()),
            ),
            (
                "cancel_losers",
                boolv(input.speculative_siblings.cancel_losers()),
            ),
            (
                "cleanup_timeout_seconds",
                super::value::int(super::value::i64v(
                    input.speculative_siblings.cleanup_timeout().as_secs(),
                    "speculative_sibling_cancellation",
                )?),
            ),
            (
                "reconcile_unknown_effects",
                boolv(input.speculative_siblings.reconcile_unknown_effects()),
            ),
        ]),
    )?;
    report.mark(141, "speculative_sibling_cancellation", FactLayer::Default);
    builder.declare(
        "writer_worktree_isolation_mode",
        SourceKind::Builtin,
        boolv(input.writer_merge.writer_worktree_isolation()),
    )?;
    report.mark(143, "writer_worktree_isolation_mode", FactLayer::Default);
    builder.observe_default(
        "merge_conflict_arbitration",
        object([
            ("on_clean", en(input.writer_merge.on_clean().label())),
            ("on_conflict", en(input.writer_merge.on_conflict().label())),
            (
                "require_verification",
                boolv(input.writer_merge.require_verification()),
            ),
        ]),
    )?;
    report.mark(144, "merge_conflict_arbitration", FactLayer::Default);
    builder.observe_default(
        "task_retry_reassignment_policy",
        object([
            (
                "max_attempts",
                super::value::int(super::value::i64u(
                    input.task_retry.max_attempts(),
                    "task_retry_reassignment_policy",
                )?),
            ),
            ("on_failure", en(input.task_retry.on_failure().label())),
            (
                "preserve_evidence",
                boolv(input.task_retry.preserve_evidence()),
            ),
        ]),
    )?;
    report.mark(146, "task_retry_reassignment_policy", FactLayer::Default);
    let stdio = input.mcp_deadlines.stdio();
    let http = input.mcp_deadlines.http();
    builder.observe_default(
        "per_server_startup_deadline",
        object([
            (
                "stdio_milliseconds",
                super::value::int(super::value::i64v(
                    stdio.startup_milliseconds(),
                    "per_server_startup_deadline",
                )?),
            ),
            (
                "http_milliseconds",
                super::value::int(super::value::i64v(
                    http.startup_milliseconds(),
                    "per_server_startup_deadline",
                )?),
            ),
        ]),
    )?;
    report.mark(150, "per_server_startup_deadline", FactLayer::Default);
    builder.observe_default(
        "per_tool_mcp_deadline",
        object([
            (
                "stdio_milliseconds",
                super::value::int(super::value::i64v(
                    stdio.tool_call_milliseconds(),
                    "per_tool_mcp_deadline",
                )?),
            ),
            (
                "http_milliseconds",
                super::value::int(super::value::i64v(
                    http.tool_call_milliseconds(),
                    "per_tool_mcp_deadline",
                )?),
            ),
        ]),
    )?;
    report.mark(151, "per_tool_mcp_deadline", FactLayer::Default);
    builder.declare(
        "mcp_result_cap_spill_policy",
        SourceKind::Builtin,
        object([
            (
                "visible_max_bytes",
                super::value::int(super::value::i64u(
                    input.mcp_result_policy.visible_max_bytes(),
                    "mcp_result_cap_spill_policy",
                )?),
            ),
            (
                "spill_max_bytes",
                super::value::int(super::value::i64u(
                    input.mcp_result_policy.spill_max_bytes(),
                    "mcp_result_cap_spill_policy",
                )?),
            ),
            ("cleanup", en(input.mcp_result_policy.cleanup().label())),
            ("private_storage", boolv(true)),
        ]),
    )?;
    report.mark(152, "mcp_result_cap_spill_policy", FactLayer::Default);
    builder.declare(
        "deferred_discovery_threshold",
        SourceKind::Builtin,
        super::value::int(super::value::i64u(
            core_tools::DEFAULT_DEFERRED_TOOL_EAGER_LIMIT,
            "deferred_discovery_threshold",
        )?),
    )?;
    report.mark(148, "deferred_discovery_threshold", FactLayer::Default);
    builder.observe_default(
        "mcp_reconnect_backoff",
        object([
            (
                "max_attempts",
                super::value::int(i64::from(input.mcp_reconnect.max_attempts())),
            ),
            (
                "base_milliseconds",
                super::value::int(super::value::i64v(
                    input.mcp_reconnect.base_ms(),
                    "mcp_reconnect_backoff",
                )?),
            ),
            (
                "cap_milliseconds",
                super::value::int(super::value::i64v(
                    input.mcp_reconnect.cap_ms(),
                    "mcp_reconnect_backoff",
                )?),
            ),
        ]),
    )?;
    report.mark(149, "mcp_reconnect_backoff", FactLayer::Default);
    add_mcp_transport(builder, input, report)?;
    add_oauth_lifecycle(builder, input, report)?;
    add_capability_exposure(builder, input, report)?;
    add_session_and_replay(builder, input, report)?;
    add_provider_governor(builder, input, report)?;
    Ok(())
}

fn add_provider_governor(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    let controls = input.provider_governor.controls;
    let rate = input.provider_governor.policy.rate_admission;
    let compression = en(controls.compression.label());
    let rate_value = object([
        (
            "minimum_remaining_requests",
            super::value::int(super::value::i64v(
                rate.minimum_remaining_requests,
                "rate_limit_aware_admission",
            )?),
        ),
        (
            "minimum_remaining_tokens",
            super::value::int(super::value::i64v(
                rate.minimum_remaining_tokens,
                "rate_limit_aware_admission",
            )?),
        ),
        (
            "reset_wait_max_seconds",
            super::value::int(super::value::i64v(
                rate.reset_wait_max.as_secs(),
                "rate_limit_aware_admission",
            )?),
        ),
        (
            "unknown_quota",
            en(match rate.unknown_quota {
                core_provider::UnknownQuotaPolicy::Conservative => "conservative",
                core_provider::UnknownQuotaPolicy::Reject => "reject",
            }),
        ),
    ]);
    let cache = controls.prompt_cache;
    let cache_value = object([
        (
            "ttl_seconds",
            super::value::int(i64::from(cache.ttl_seconds)),
        ),
        ("breakpoint", en(cache.breakpoint.label())),
        (
            "invalidate_on_tool_change",
            boolv(cache.invalidate_on_tool_change),
        ),
        ("scope", en(cache.scope.label())),
    ]);
    if input.provider_governor_configured {
        builder.declare(
            "request_compression_policy",
            SourceKind::UserConfig,
            compression,
        )?;
        builder.declare(
            "rate_limit_aware_admission",
            SourceKind::UserConfig,
            rate_value,
        )?;
        builder.declare(
            "prompt_cache_ttl_breakpoint_strategy",
            SourceKind::UserConfig,
            cache_value,
        )?;
    } else {
        builder.observe_default("request_compression_policy", compression)?;
        builder.observe_default("rate_limit_aware_admission", rate_value)?;
        builder.observe_default("prompt_cache_ttl_breakpoint_strategy", cache_value)?;
    }
    for (ordinal, family) in [
        (155, "request_compression_policy"),
        (157, "rate_limit_aware_admission"),
        (158, "prompt_cache_ttl_breakpoint_strategy"),
    ] {
        report.mark(ordinal, family, FactLayer::Default);
    }
    Ok(())
}

fn add_capability_exposure(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    let names = input
        .registry
        .specs()
        .into_iter()
        .map(|spec| spec.name)
        .collect::<BTreeSet<_>>();
    let resources = names
        .iter()
        .filter(|name| name.ends_with("__resources_list") || name.ends_with("__resources_read"))
        .cloned()
        .collect::<Vec<_>>();
    let prompts = names
        .iter()
        .filter(|name| name.ends_with("__prompts_list") || name.ends_with("__prompts_get"))
        .cloned()
        .collect::<Vec<_>>();
    if resources.is_empty() && prompts.is_empty() {
        return Ok(());
    }
    builder.declare(
        "resource_prompt_plugin_capability_exposure",
        SourceKind::RuntimeObservation,
        object([
            (
                "resource_discovery",
                en(if resources.is_empty() {
                    "disabled"
                } else {
                    "lazy"
                }),
            ),
            (
                "prompt_discovery",
                en(if prompts.is_empty() {
                    "disabled"
                } else {
                    "lazy"
                }),
            ),
            (
                "resource_tool_ids",
                super::value::list(resources.iter().map(|name| text(name))),
            ),
            (
                "prompt_tool_ids",
                super::value::list(prompts.iter().map(|name| text(name))),
            ),
            (
                "max_visible_bytes",
                super::value::int(super::value::i64u(
                    input.mcp_result_policy.visible_max_bytes(),
                    "resource_prompt_plugin_capability_exposure",
                )?),
            ),
        ]),
    )?;
    report.mark(
        154,
        "resource_prompt_plugin_capability_exposure",
        FactLayer::Default,
    );
    Ok(())
}

fn add_child_defaults(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    let Some(child) = input.child_overlay else {
        for (ordinal, family) in [
            (133, "per_agent_model"),
            (134, "per_agent_effort_thinking"),
            (135, "per_agent_tool_profile"),
        ] {
            unsupported(
                builder,
                report,
                ordinal,
                family,
                ExtensionGapReason::RequiredOwnerObservationMissing,
                GapImpact::Blocking,
            )?;
        }
        return Ok(());
    };

    builder.observe_default(
        "per_agent_model",
        en(&format!("{}:{}", child.provider_id, child.model_id)),
    )?;
    report.mark(133, "per_agent_model", FactLayer::Default);
    builder.observe_default("per_agent_effort_thinking", en(child.effort.label()))?;
    report.mark(134, "per_agent_effort_thinking", FactLayer::Default);
    builder.observe_default(
        "per_agent_tool_profile",
        super::value::tool_profile(&child.tool_profile),
    )?;
    report.mark(135, "per_agent_tool_profile", FactLayer::Default);

    if let Some(memory) = &child.memory_scope {
        let value = if let Some(scope_id) = memory.scope_id.as_deref() {
            object([
                ("mode", en(memory_mode(memory.mode))),
                ("scope_id", text(scope_id)),
                ("inherit_parent", boolv(memory.inherit_parent)),
            ])
        } else {
            object([
                ("mode", en(memory_mode(memory.mode))),
                ("inherit_parent", boolv(memory.inherit_parent)),
            ])
        };
        builder.declare("per_agent_memory_scope", SourceKind::Builtin, value)?;
        report.mark(136, "per_agent_memory_scope", FactLayer::Default);
    }
    Ok(())
}

fn add_mcp_transport(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    let transports = input
        .configured_mcp
        .iter()
        .map(|server| match server.transport {
            McpTransportConfig::Stdio => McpTransport::Stdio,
            McpTransportConfig::Http => McpTransport::Http,
        })
        .collect::<BTreeSet<_>>();
    if !transports.is_empty() {
        builder.declare(
            "mcp_transport_selection",
            SourceKind::UserConfig,
            super::value::list(
                transports
                    .iter()
                    .map(|transport| en(super::value::transport(*transport))),
            ),
        )?;
        report.mark(147, "mcp_transport_selection", FactLayer::Default);
    }
    Ok(())
}

fn add_oauth_lifecycle(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    let oauth = input
        .configured_mcp
        .iter()
        .filter_map(|server| server.oauth.as_ref())
        .collect::<Vec<_>>();
    if oauth.is_empty() {
        return Ok(());
    }
    let refresh_count = oauth
        .iter()
        .filter(|config| config.refresh_url.is_some() && config.refresh_token_env.is_some())
        .count();
    let revocation_count = oauth
        .iter()
        .filter(|config| {
            config.refresh_url.is_some()
                && config.refresh_token_env.is_some()
                && config.revoke_url.is_some()
        })
        .count();
    let mode = match (refresh_count, oauth.len()) {
        (0, _) => OAuthLifecycleMode::Bearer,
        (refresh, total) if refresh == total => OAuthLifecycleMode::RefreshToken,
        _ => OAuthLifecycleMode::Mixed,
    };
    let binding_count = super::value::i64u(oauth.len(), "oauth_auth_lifecycle_policy")?;
    let refresh_count = super::value::i64u(refresh_count, "oauth_auth_lifecycle_policy")?;
    let revocation_count = super::value::i64u(revocation_count, "oauth_auth_lifecycle_policy")?;
    builder.declare(
        "oauth_auth_lifecycle_policy",
        SourceKind::UserConfig,
        object([
            ("credential_mode", en(super::value::oauth_mode(mode))),
            ("binding_count", super::value::int(binding_count)),
            ("refresh_binding_count", super::value::int(refresh_count)),
            (
                "revocation_binding_count",
                super::value::int(revocation_count),
            ),
            (
                "refresh_before_expiry_when_capable",
                boolv(refresh_count > 0),
            ),
            (
                "retry_once_after_unauthorized_when_capable",
                boolv(refresh_count > 0),
            ),
            ("revoke_access_after_forbidden", boolv(true)),
            (
                "expiry_skew_seconds",
                super::value::int(core_mcp::token::EXPIRY_SKEW_SECS as i64),
            ),
            (
                "revocation_endpoint_configured",
                boolv(revocation_count > 0),
            ),
        ]),
    )?;
    report.mark(153, "oauth_auth_lifecycle_policy", FactLayer::Default);
    Ok(())
}

fn add_session_and_replay(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    builder.declare(
        "session_isolation_profile",
        SourceKind::Builtin,
        en(session_profile(input.session_profile)),
    )?;
    report.mark(159, "session_isolation_profile", FactLayer::Default);

    if input.replay_owner.fail_closed {
        builder.declare(
            "replay_divergence_detection_policy",
            SourceKind::Builtin,
            replay_policy(input.replay_owner),
        )?;
        report.mark(
            160,
            "replay_divergence_detection_policy",
            FactLayer::Default,
        );
    } else {
        report.gap(
            160,
            "replay_divergence_detection_policy",
            FactLayer::Default,
            ExtensionGapReason::OwnerSchemaMismatch,
            GapImpact::Blocking,
        );
    }
    Ok(())
}

fn unsupported(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ExtensionFactsReport,
    ordinal: u16,
    family: &'static str,
    reason: ExtensionGapReason,
    impact: GapImpact,
) -> Result<(), ExtensionFactError> {
    builder.observe_default_unsupported(family, reason.code())?;
    report.gap(ordinal, family, FactLayer::Default, reason, impact);
    Ok(())
}
