use super::*;

use iteron_protocol::{Capability, Effort};
use iteron_tunables::{DecimalValue, FixedAuthorityId, ResolutionValue, SourceKind, TunableValue};
use std::collections::BTreeMap;

use crate::runtime_tunables::fixed_artifacts::FixedAuthoritySample;

/// Re-sample immutable execution owners directly from the implementations that execute them.
/// Session/route/budget-derived fixed values are checkpoint-reconstructed and intentionally absent.
pub(crate) fn live_fixed_authority_samples() -> Result<Vec<FixedAuthoritySample>, ExecutionFactError>
{
    Ok(vec![
        FixedAuthoritySample {
            family: "pure_overlap",
            authority: FixedAuthorityId::StrategyInvariant,
            value: boolv(iteron_tools::Registry::pure_overlap_owner()),
        },
        FixedAuthoritySample {
            family: "pure_concurrency",
            authority: FixedAuthorityId::StrategyInvariant,
            value: int(i64u(
                crate::runtime::DEFAULT_MAX_TOOL_CONCURRENCY,
                "pure_concurrency",
            )?),
        },
        FixedAuthoritySample {
            family: "failed_action_dedup",
            authority: FixedAuthorityId::StrategyInvariant,
            value: crate::runtime::FailedActionCache::tunable_value(),
        },
        FixedAuthoritySample {
            family: "pure_memo_cache",
            authority: FixedAuthorityId::StrategyInvariant,
            value: pure_memo_cache_value(iteron_tools::PureMemoCachePolicy::production_owner())?,
        },
        FixedAuthoritySample {
            family: "web_search_cap",
            authority: FixedAuthorityId::StrategyInvariant,
            value: int(i64u(iteron_tools::WEB_SEARCH_RESULT_CAP, "web_search_cap")?),
        },
        FixedAuthoritySample {
            family: "verifier_attempts",
            authority: FixedAuthorityId::StrategyInvariant,
            value: int(i64::from(iteron_verify::strategy::MAX_VERIFIER_ATTEMPTS)),
        },
        FixedAuthoritySample {
            family: "token_split",
            authority: FixedAuthorityId::StrategyInvariant,
            value: ResolutionValue::Decimal {
                value: token_split()?,
            },
        },
        FixedAuthoritySample {
            family: "join_reduce",
            authority: FixedAuthorityId::StrategyInvariant,
            value: join_reduce_owner_value(),
        },
    ])
}

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    observe_fixed(
        builder,
        report,
        "pure_overlap",
        FixedAuthorityId::StrategyInvariant,
        boolv(input.registry.pure_overlap_enabled()),
        boolv(input.registry.pure_overlap_enabled()),
    )?;
    let pure_concurrency = int(i64u(
        crate::runtime::DEFAULT_MAX_TOOL_CONCURRENCY,
        "pure_concurrency",
    )?);
    observe_fixed(
        builder,
        report,
        "pure_concurrency",
        FixedAuthorityId::StrategyInvariant,
        pure_concurrency.clone(),
        pure_concurrency,
    )?;
    let failed_action_dedup = crate::runtime::FailedActionCache::tunable_value();
    observe_fixed(
        builder,
        report,
        "failed_action_dedup",
        FixedAuthorityId::StrategyInvariant,
        failed_action_dedup.clone(),
        failed_action_dedup,
    )?;
    let pure_memo_cache = pure_memo_cache_value(input.registry.pure_memo_cache_policy())?;
    observe_fixed(
        builder,
        report,
        "pure_memo_cache",
        FixedAuthorityId::StrategyInvariant,
        pure_memo_cache.clone(),
        pure_memo_cache,
    )?;
    let web_search_cap = int(i64u(iteron_tools::WEB_SEARCH_RESULT_CAP, "web_search_cap")?);
    observe_fixed(
        builder,
        report,
        "web_search_cap",
        FixedAuthorityId::StrategyInvariant,
        web_search_cap.clone(),
        web_search_cap,
    )?;

    let provider_connect_timeout = provider_connect_timeout_owner_value()?;
    builder.attest_literal_owner(
        "provider_connect_tls_timeout",
        provider_connect_timeout.clone(),
    )?;
    builder.attest_fixed_authority(
        "provider_connect_tls_timeout",
        FixedAuthorityId::StrategyInvariant,
        int(provider_connect_timeout_seconds()?.min(i64v(
            input.budget.max_wall_secs,
            "provider_connect_tls_timeout",
        )?)),
    )?;

    let discovery = crate::providers::ProviderDiscoveryPolicy::owner();
    let discovery_value = object([
        (
            "eager_budget_milliseconds",
            int(i64v(
                discovery.eager_budget_milliseconds(),
                "provider_discovery_account_probe_cache_policy",
            )?),
        ),
        (
            "positive_ttl_seconds",
            int(i64v(
                discovery.positive_ttl_seconds(),
                "provider_discovery_account_probe_cache_policy",
            )?),
        ),
        (
            "failure_backoff_base_seconds",
            int(i64v(
                discovery.failure_backoff_base_seconds(),
                "provider_discovery_account_probe_cache_policy",
            )?),
        ),
        (
            "failure_backoff_cap_seconds",
            int(i64v(
                discovery.failure_backoff_cap_seconds(),
                "provider_discovery_account_probe_cache_policy",
            )?),
        ),
    ]);
    attest_literal_owner(
        builder,
        report,
        "provider_discovery_account_probe_cache_policy",
        discovery_value.clone(),
    )?;
    if input
        .route
        .capabilities
        .contains(&iteron_tunables::CapabilityRequirement::ProviderDiscovery)
    {
        builder.attest_fixed_authority(
            "provider_discovery_account_probe_cache_policy",
            FixedAuthorityId::ProviderDiscoveryBootstrap,
            discovery_value,
        )?;
    }

    let verifier_attempts = int(i64::from(iteron_verify::strategy::MAX_VERIFIER_ATTEMPTS));
    observe_fixed(
        builder,
        report,
        "verifier_attempts",
        FixedAuthorityId::StrategyInvariant,
        verifier_attempts.clone(),
        verifier_attempts,
    )?;
    let feedback = iteron_verify::VerificationFeedbackTailPolicy::default();
    observe(
        builder,
        report,
        "verifier_feedback_tails",
        object([
            (
                "command_output_bytes",
                int(i64u(
                    feedback.command_output_bytes,
                    "verifier_feedback_tails",
                )?),
            ),
            (
                "oracle_output_bytes",
                int(i64u(
                    feedback.oracle_output_bytes,
                    "verifier_feedback_tails",
                )?),
            ),
            (
                "total_bytes",
                int(i64u(feedback.total_bytes, "verifier_feedback_tails")?),
            ),
        ]),
    )?;
    let verifier_timeout = int(i64v(
        iteron_verify::DEFAULT_VERIFIER_TIMEOUT_SECS.min(input.budget.max_wall_secs),
        "verifier_timeout",
    )?);
    observe_fixed(
        builder,
        report,
        "verifier_timeout",
        FixedAuthorityId::RuntimeInvariant,
        verifier_timeout.clone(),
        verifier_timeout,
    )?;
    let decomposition = iteron_agents::DecompositionProfile::owner();
    let decomposition_default = object([
        (
            "max_output_tokens",
            int(i64v(
                decomposition.max_output_tokens,
                "decomposition_profile",
            )?),
        ),
        ("effort", en(decomposition.effort.label())),
        (
            "thinking_tokens",
            int(i64::from(decomposition.thinking_tokens)),
        ),
    ]);
    observe(
        builder,
        report,
        "decomposition_profile",
        decomposition_default,
    )?;
    builder.attest_fixed_authority(
        "decomposition_profile",
        FixedAuthorityId::StrategyInvariant,
        object([
            (
                "max_output_tokens",
                int(i64v(
                    decomposition
                        .max_output_tokens
                        .min(input.budget.max_tokens.unwrap_or(65_536)),
                    "decomposition_profile",
                )?),
            ),
            ("effort", en(decomposition.effort.label())),
            (
                "thinking_tokens",
                int(i64::from(decomposition.thinking_tokens)),
            ),
        ]),
    )?;
    let fan_breadth_default = int(i64u(iteron_agents::FAN_CAP, "fan_breadth")?);
    let fan_breadth_effective = int(i64u(
        iteron_agents::FAN_CAP.min(input.run_limits.max_agent_calls()),
        "fan_breadth",
    )?);
    observe_fixed(
        builder,
        report,
        "fan_breadth",
        FixedAuthorityId::StrategyInvariant,
        fan_breadth_default,
        fan_breadth_effective,
    )?;
    let minimum_worker_turns = worker_min_turns()?;
    observe_fixed(
        builder,
        report,
        "worker_min_turns",
        FixedAuthorityId::StrategyInvariant,
        int(i64::from(minimum_worker_turns)),
        int(i64::from(minimum_worker_turns.min(input.budget.max_turns))),
    )?;
    let token_split = ResolutionValue::Decimal {
        value: token_split()?,
    };
    observe_fixed(
        builder,
        report,
        "token_split",
        FixedAuthorityId::StrategyInvariant,
        token_split.clone(),
        token_split,
    )?;
    let limits = iteron_workflow::RunLimits::default();
    observe_fixed(
        builder,
        report,
        "fan_concurrency",
        FixedAuthorityId::StrategyInvariant,
        int(i64u(limits.max_concurrency(), "fan_concurrency")?),
        int(i64u(
            limits
                .max_concurrency()
                .min(input.run_limits.max_concurrency()),
            "fan_concurrency",
        )?),
    )?;

    let execution = super::super::execution_policy::ExecutionRuntimePolicy::owner(
        input.effort,
        input.budget,
        input.run_limits,
    );
    let route_topology = en(match execution.route_topology {
        super::super::execution_policy::RouteTopology::Direct => "direct",
        super::super::execution_policy::RouteTopology::Orchestrated => "orchestrated",
    });
    observe_fixed(
        builder,
        report,
        "route_topology",
        FixedAuthorityId::StrategyInvariant,
        route_topology.clone(),
        route_topology,
    )?;
    let admission_default = object([
        (
            "minimum_remaining_turns",
            int(i64::from(execution.admission.minimum_remaining_turns)),
        ),
        (
            "minimum_remaining_wall_seconds",
            int(i64v(
                execution.admission.minimum_remaining_wall_seconds,
                "admission",
            )?),
        ),
        (
            "require_capability_subset",
            boolv(execution.admission.require_capability_subset),
        ),
    ]);
    let admission_effective = object([
        (
            "minimum_remaining_turns",
            int(i64::from(
                execution
                    .admission
                    .minimum_remaining_turns
                    .min(input.budget.max_turns),
            )),
        ),
        (
            "minimum_remaining_wall_seconds",
            int(i64v(
                execution
                    .admission
                    .minimum_remaining_wall_seconds
                    .min(input.budget.max_wall_secs),
                "admission",
            )?),
        ),
        (
            "require_capability_subset",
            boolv(execution.admission.require_capability_subset),
        ),
    ]);
    observe_fixed(
        builder,
        report,
        "admission",
        FixedAuthorityId::StrategyInvariant,
        admission_default,
        admission_effective,
    )?;
    let writer_fan_turn_split_default = object([
        (
            "writer_numerator",
            int(i64::from(
                execution.writer_fan_turn_split.writer_share.numerator,
            )),
        ),
        (
            "writer_denominator",
            int(i64::from(
                execution.writer_fan_turn_split.writer_share.denominator,
            )),
        ),
        (
            "minimum_writer_turns",
            int(i64::from(
                execution.writer_fan_turn_split.minimum_writer_turns,
            )),
        ),
        (
            "strictly_dominant",
            boolv(execution.writer_fan_turn_split.strictly_dominant),
        ),
    ]);
    let writer_fan_turn_split_effective = object([
        (
            "writer_numerator",
            int(i64::from(
                execution.writer_fan_turn_split.writer_share.numerator,
            )),
        ),
        (
            "writer_denominator",
            int(i64::from(
                execution.writer_fan_turn_split.writer_share.denominator,
            )),
        ),
        (
            "minimum_writer_turns",
            int(i64::from(
                execution
                    .writer_fan_turn_split
                    .minimum_writer_turns
                    .min(input.budget.max_turns),
            )),
        ),
        (
            "strictly_dominant",
            boolv(execution.writer_fan_turn_split.strictly_dominant),
        ),
    ]);
    observe_fixed(
        builder,
        report,
        "writer_fan_turn_split",
        FixedAuthorityId::StrategyInvariant,
        writer_fan_turn_split_default,
        writer_fan_turn_split_effective,
    )?;
    let wall_split_default = object([
        (
            "fan_numerator",
            int(i64::from(execution.wall_split.fan_share.numerator)),
        ),
        (
            "fan_denominator",
            int(i64::from(execution.wall_split.fan_share.denominator)),
        ),
        (
            "minimum_fan_seconds",
            int(i64v(
                execution.wall_split.minimum_fan_seconds,
                "wall_split",
            )?),
        ),
    ]);
    let wall_split_effective = object([
        (
            "fan_numerator",
            int(i64::from(execution.wall_split.fan_share.numerator)),
        ),
        (
            "fan_denominator",
            int(i64::from(execution.wall_split.fan_share.denominator)),
        ),
        (
            "minimum_fan_seconds",
            int(i64v(
                execution
                    .wall_split
                    .minimum_fan_seconds
                    .min(input.budget.max_wall_secs),
                "wall_split",
            )?),
        ),
    ]);
    observe_fixed(
        builder,
        report,
        "wall_split",
        FixedAuthorityId::StrategyInvariant,
        wall_split_default,
        wall_split_effective,
    )?;
    let direct = execution.direct_child_allocation;
    observe(
        builder,
        report,
        "direct_child_allocation",
        object([
            (
                "writer_turn_numerator",
                int(i64::from(direct.writer_share.numerator)),
            ),
            (
                "writer_turn_denominator",
                int(i64::from(direct.writer_share.denominator)),
            ),
            (
                "strictly_dominant_writer",
                boolv(direct.strictly_dominant_writer),
            ),
            (
                "child_token_numerator",
                int(i64::from(direct.child_token_share.numerator)),
            ),
            (
                "child_token_denominator",
                int(i64::from(direct.child_token_share.denominator)),
            ),
            (
                "child_wall_numerator",
                int(i64::from(direct.child_wall_share.numerator)),
            ),
            (
                "child_wall_denominator",
                int(i64::from(direct.child_wall_share.denominator)),
            ),
            (
                "minimum_child_turns",
                int(i64::from(direct.minimum_child_turns)),
            ),
            (
                "minimum_remaining_wall_seconds",
                int(i64v(
                    direct.minimum_remaining_wall_seconds,
                    "direct_child_allocation",
                )?),
            ),
        ]),
    )?;
    let subagent_effort = en(execution.subagent_effort.label());
    observe(
        builder,
        report,
        "subagent_effort_inheritance",
        subagent_effort.clone(),
    )?;
    builder.attest_fixed_authority(
        "subagent_effort_inheritance",
        FixedAuthorityId::StrategyInvariant,
        subagent_effort,
    )?;
    let report_budget = int(i64u(execution.report_budget_bytes, "report_budget")?);
    observe_fixed(
        builder,
        report,
        "report_budget",
        FixedAuthorityId::StrategyInvariant,
        report_budget.clone(),
        report_budget,
    )?;
    let mut workflow_fields = BTreeMap::from([
        (
            "max_calls".to_owned(),
            int(i64u(execution.workflow.max_calls, "workflow_aggregate")?),
        ),
        (
            "max_wall_seconds".to_owned(),
            int(i64v(
                execution.workflow.max_wall_seconds,
                "workflow_aggregate",
            )?),
        ),
        (
            "max_concurrency".to_owned(),
            int(i64u(
                execution.workflow.max_concurrency,
                "workflow_aggregate",
            )?),
        ),
    ]);
    if let Some(tokens) = execution.workflow.max_tokens {
        workflow_fields.insert(
            "max_tokens".into(),
            int(i64v(tokens, "workflow_aggregate")?),
        );
    }
    observe(
        builder,
        report,
        "workflow_aggregate",
        ResolutionValue::Object {
            fields: workflow_fields,
        },
    )?;
    observe(
        builder,
        report,
        "schema_retry_jitter",
        object([
            (
                "max_attempts",
                int(i64::from(execution.schema_retry.max_attempts())),
            ),
            (
                "base_milliseconds",
                int(i64v(
                    execution.schema_retry.base_ms(),
                    "schema_retry_jitter",
                )?),
            ),
            (
                "cap_milliseconds",
                int(i64v(
                    execution.schema_retry.cap_ms(),
                    "schema_retry_jitter",
                )?),
            ),
        ]),
    )?;
    let queue = crate::app_server::AppServerQueuePolicy::owner();
    attest_literal_owner(
        builder,
        report,
        "app_server_sq_eq_backpressure",
        object([
            (
                "submission_entries",
                int(i64u(
                    queue.submission_entries(),
                    "app_server_sq_eq_backpressure",
                )?),
            ),
            (
                "submission_bytes",
                int(i64u(
                    queue.submission_bytes(),
                    "app_server_sq_eq_backpressure",
                )?),
            ),
            (
                "event_entries",
                int(i64u(
                    queue.event_entries(),
                    "app_server_sq_eq_backpressure",
                )?),
            ),
            (
                "cosmetic_overflow",
                en(match queue.cosmetic_overflow() {
                    crate::app_server::CosmeticOverflow::Drop => "drop",
                    crate::app_server::CosmeticOverflow::Coalesce => "coalesce",
                }),
            ),
            (
                "authoritative_overflow",
                en(match queue.authoritative_overflow() {
                    crate::app_server::AuthoritativeOverflow::Wait => "wait",
                    crate::app_server::AuthoritativeOverflow::Reject => "reject",
                }),
            ),
        ]),
    )?;

    // Operator text is durable private record content, not configuration truth. Family 71 is a
    // fixed authority marker and remains inactive until a real private materializer can attest an
    // exact content-free receipt before the run is opened. Hashing the caller's raw string here
    // would only be self-attestation and would make a checkpoint claim a materializer that does
    // not exist.

    if let Some(hooks) = input.hooks_catalog.as_ref() {
        builder.declare(
            "hooks_map",
            SourceKind::UserConfig,
            hook_catalog_value(hooks)?,
        )?;
        report.mark("hooks_map", FactStage::Default);
    }
    let workflow_graph = iteron_workflow::workflow_graph_runtime_identity();
    observe(
        builder,
        report,
        "workflow_graph",
        workflow_graph_value(&workflow_graph)?,
    )?;
    let environment =
        iteron_protocol::EnvironmentSnapshotIdentity::from_optional(input.environment);
    let environment = environment_snapshot_value(&environment)?;
    observe_fixed(
        builder,
        report,
        "environment_snapshot",
        FixedAuthorityId::RuntimeInvariant,
        environment.clone(),
        environment,
    )?;

    // Family 68 is registry-literal because these are hard decoder/admission invariants rather
    // than a runtime-selected policy. Still compare the literal against the actual rejecting
    // owner on every fresh composition: a code/schema drift must abort resolution, not leave a
    // plausible-looking checkpoint whose bytes are not enforced by the loader.
    let multimodal = crate::image_input::multimodal_decode_envelope();
    attest_literal_owner(
        builder,
        report,
        "multimodal_input_admission_decode_envelope",
        multimodal_decode_envelope_value(multimodal)?,
    )?;

    // The governed catalog default is the content-free identity of the exact executable
    // definitions already discovered at the composition root. The pure resolver never executes
    // catalog bytes; the consumer later compares this identity with the catalog it is about to
    // install.
    observe(
        builder,
        report,
        "agent_catalog",
        agent_catalog_value(&input.agent_catalog.runtime_identity())?,
    )?;

    let observation = iteron_tools::ObservationToolPolicy::default();
    observe(
        builder,
        report,
        "read_file_limits",
        object([
            (
                "source_max_bytes",
                int(i64u(
                    observation.read_file.source_max_bytes,
                    "read_file_limits",
                )?),
            ),
            (
                "output_max_bytes",
                int(i64u(
                    observation.read_file.output_max_bytes,
                    "read_file_limits",
                )?),
            ),
            (
                "max_lines",
                int(i64u(observation.read_file.max_lines, "read_file_limits")?),
            ),
        ]),
    )?;
    observe(
        builder,
        report,
        "list_dir_limits",
        object([
            (
                "max_depth",
                int(i64u(observation.list_dir.max_depth, "list_dir_limits")?),
            ),
            (
                "max_entries",
                int(i64u(observation.list_dir.max_entries, "list_dir_limits")?),
            ),
            (
                "output_max_bytes",
                int(i64u(
                    observation.list_dir.output_max_bytes,
                    "list_dir_limits",
                )?),
            ),
        ]),
    )?;
    observe(
        builder,
        report,
        "glob_limits",
        object([
            (
                "max_depth",
                int(i64u(observation.glob.max_depth, "glob_limits")?),
            ),
            (
                "max_results",
                int(i64u(observation.glob.max_results, "glob_limits")?),
            ),
            (
                "output_max_bytes",
                int(i64u(observation.glob.output_max_bytes, "glob_limits")?),
            ),
        ]),
    )?;
    observe(
        builder,
        report,
        "repo_map",
        object([
            (
                "max_files",
                int(i64u(observation.repo_map.max_files, "repo_map")?),
            ),
            ("max_depth", int(i64::from(observation.repo_map.max_depth))),
            (
                "max_tokens",
                int(i64u(observation.repo_map.max_tokens, "repo_map")?),
            ),
        ]),
    )?;
    observe(
        builder,
        report,
        "web_fetch_limits",
        object([
            (
                "body_max_bytes",
                int(i64u(
                    observation.web_fetch.body_max_bytes,
                    "web_fetch_limits",
                )?),
            ),
            (
                "max_redirects",
                int(i64u(
                    observation.web_fetch.max_redirects,
                    "web_fetch_limits",
                )?),
            ),
            (
                "timeout_seconds",
                int(i64v(
                    observation.web_fetch.timeout_seconds,
                    "web_fetch_limits",
                )?),
            ),
            (
                "max_lines",
                int(i64u(observation.web_fetch.max_lines, "web_fetch_limits")?),
            ),
        ]),
    )?;
    attest_literal_owner(
        builder,
        report,
        "shell_timeout_output",
        object([
            (
                "timeout_seconds",
                int(i64v(
                    observation.shell.timeout_seconds,
                    "shell_timeout_output",
                )?),
            ),
            (
                "stdout_max_bytes",
                int(i64u(
                    observation.shell.stdout_max_bytes,
                    "shell_timeout_output",
                )?),
            ),
            (
                "stderr_max_bytes",
                int(i64u(
                    observation.shell.stderr_max_bytes,
                    "shell_timeout_output",
                )?),
            ),
        ]),
    )?;
    observe(
        builder,
        report,
        "grep_limits",
        object([
            (
                "max_matches",
                int(i64u(observation.grep.max_matches, "grep_limits")?),
            ),
            (
                "snippet_max_bytes",
                int(i64u(observation.grep.snippet_max_bytes, "grep_limits")?),
            ),
            (
                "output_max_bytes",
                int(i64u(observation.grep.output_max_bytes, "grep_limits")?),
            ),
        ]),
    )?;
    observe(
        builder,
        report,
        "git_limits",
        object([
            (
                "timeout_seconds",
                int(i64v(observation.git.timeout_seconds, "git_limits")?),
            ),
            (
                "output_max_bytes",
                int(i64u(observation.git.output_max_bytes, "git_limits")?),
            ),
            (
                "status_max_entries",
                int(i64u(observation.git.status_max_entries, "git_limits")?),
            ),
            (
                "log_max_entries",
                int(i64u(observation.git.log_max_entries, "git_limits")?),
            ),
        ]),
    )?;

    let child = iteron_agents::subagent_budget_ceiling();
    let child_capabilities = CapabilitySet::only(Capability::ReadOnly);
    let child_ceiling_default = object([
        ("max_turns", int(i64::from(child.max_turns))),
        (
            "max_wall_seconds",
            int(i64v(child.max_wall_secs, "child_ceiling")?),
        ),
        (
            "max_consecutive_errors",
            int(i64::from(child.max_consecutive_tool_errors)),
        ),
        ("capabilities", capability_list(child_capabilities)),
    ]);
    let admitted_child_capabilities = input
        .authority_ceiling
        .intersect(CapabilitySet::only(Capability::ReadOnly));
    let child_ceiling_effective = object([
        (
            "max_turns",
            int(i64::from(child.max_turns.min(input.budget.max_turns))),
        ),
        (
            "max_wall_seconds",
            int(i64v(
                child.max_wall_secs.min(input.budget.max_wall_secs),
                "child_ceiling",
            )?),
        ),
        (
            "max_consecutive_errors",
            int(i64::from(child.max_consecutive_tool_errors)),
        ),
        ("capabilities", capability_list(admitted_child_capabilities)),
    ]);
    observe(builder, report, "child_ceiling", child_ceiling_default)?;
    if admitted_child_capabilities.contains(Capability::ReadOnly) {
        builder.attest_fixed_authority(
            "child_ceiling",
            FixedAuthorityId::KernelInvariant,
            child_ceiling_effective,
        )?;
    }

    let join_reduce = join_reduce_owner_value();
    observe_fixed(
        builder,
        report,
        "join_reduce",
        FixedAuthorityId::StrategyInvariant,
        join_reduce.clone(),
        join_reduce,
    )?;

    // Operator text is durable private record content, not configuration truth.  Family 71 is a
    // fixed authority marker and therefore remains inactive in the V2 tunables projection; the
    // actual prompt is committed by the record field/CAS path.  Persisting `prompt` here would put
    // arbitrary user content into a checkpoint whose protocol contract is explicitly content-free.

    record_non_catalog_default_gaps(report);
    Ok(())
}

pub(super) fn record_catalog_and_owner_gaps(
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) {
    for family in [
        "builtin_prompt_corpus",
        "instruction_bundle",
        "memory_corpus",
        "skill_catalog",
        "provider_model_capability_catalog",
        "tool_action_space",
        "rate_card_catalog",
        "router_lexicons",
    ] {
        report.gap(
            family,
            FactStage::Default,
            GapReason::GovernedCatalogNotAdmissible,
        );
    }
    if !input.configured_mcp.is_empty() {
        report.gap(
            "mcp_topology_tool_catalog",
            FactStage::Default,
            GapReason::GovernedCatalogNotAdmissible,
        );
    }
    if input.inventory_web_search() {
        report.gap(
            "web_search_backend_catalog",
            FactStage::Inventory,
            GapReason::CredentialFreeWebInventoryUnavailable,
        );
        report.gap(
            "web_search_backend_catalog",
            FactStage::Default,
            GapReason::GovernedCatalogNotAdmissible,
        );
    }
}

fn record_non_catalog_default_gaps(_report: &mut ExecutionFactsReport) {}

fn worker_min_turns() -> Result<u32, ExecutionFactError> {
    Ok(iteron_agents::MIN_SUBAGENT_TURNS)
}

fn token_split() -> Result<DecimalValue, ExecutionFactError> {
    let observed = iteron_agents::subagent_budget(8, 3, Some(100))
        .and_then(|budget| budget.max_tokens)
        .ok_or(ExecutionFactError::ChildAllocationUnavailable)?;
    let mut coefficient = i64v(observed, "token_split")?;
    let mut scale = 2;
    while scale > 0 && coefficient % 10 == 0 {
        coefficient /= 10;
        scale -= 1;
    }
    Ok(DecimalValue { coefficient, scale })
}

fn pure_memo_cache_value(
    memo: iteron_tools::PureMemoCachePolicy,
) -> Result<ResolutionValue, ExecutionFactError> {
    Ok(object([
        (
            "max_entries",
            int(i64u(memo.max_entries, "pure_memo_cache")?),
        ),
        (
            "max_key_bytes",
            int(i64u(memo.max_key_bytes, "pure_memo_cache")?),
        ),
        ("generation_scoped", boolv(memo.generation_scoped)),
    ]))
}

fn join_reduce_owner_value() -> ResolutionValue {
    let owner = iteron_agents::join_reduce_policy();
    object([
        ("join", en(owner.join.id())),
        ("order", en(owner.order.id())),
        (
            "include_failed_evidence",
            boolv(owner.include_failed_evidence),
        ),
    ])
}

fn provider_connect_timeout_owner_value() -> Result<ResolutionValue, ExecutionFactError> {
    Ok(int(provider_connect_timeout_seconds()?))
}

fn provider_connect_timeout_seconds() -> Result<i64, ExecutionFactError> {
    i64v(
        iteron_provider::provider_connect_timeout().as_secs(),
        "provider_connect_tls_timeout",
    )
}

fn observe(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ExecutionFactsReport,
    family: &'static str,
    value: ResolutionValue,
) -> Result<(), ExecutionFactError> {
    builder.observe_default(family, value)?;
    report.mark(family, FactStage::Default);
    Ok(())
}

fn observe_fixed(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ExecutionFactsReport,
    family: &'static str,
    authority: FixedAuthorityId,
    default_value: ResolutionValue,
    effective_owner_value: ResolutionValue,
) -> Result<(), ExecutionFactError> {
    observe(builder, report, family, default_value)?;
    builder.attest_fixed_authority(family, authority, effective_owner_value)?;
    Ok(())
}

pub(super) fn int(value: i64) -> ResolutionValue {
    ResolutionValue::Integer { value }
}

pub(super) fn boolv(value: bool) -> ResolutionValue {
    ResolutionValue::Boolean { value }
}

pub(super) fn text(value: &str) -> ResolutionValue {
    ResolutionValue::Text {
        value: value.to_owned(),
    }
}

pub(super) fn en(value: &str) -> ResolutionValue {
    ResolutionValue::Enum {
        value: value.to_owned(),
    }
}

pub(super) fn object<const N: usize>(values: [(&str, ResolutionValue); N]) -> ResolutionValue {
    ResolutionValue::Object {
        fields: values
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<BTreeMap<_, _>>(),
    }
}

pub(super) fn multimodal_decode_envelope_value(
    policy: crate::image_input::MultimodalDecodeEnvelope,
) -> Result<ResolutionValue, ExecutionFactError> {
    Ok(object([
        (
            "max_images",
            int(i64u(
                policy.max_images,
                "multimodal_input_admission_decode_envelope",
            )?),
        ),
        (
            "per_image_raw_bytes",
            int(i64u(
                policy.per_image_raw_bytes,
                "multimodal_input_admission_decode_envelope",
            )?),
        ),
        (
            "aggregate_raw_bytes",
            int(i64u(
                policy.aggregate_raw_bytes,
                "multimodal_input_admission_decode_envelope",
            )?),
        ),
        ("max_dimension", int(i64::from(policy.max_dimension))),
        ("max_frames", int(i64::from(policy.max_frames))),
    ]))
}

pub(super) fn agent_catalog_value(
    identity: &iteron_agents::AgentCatalogRuntimeIdentity,
) -> Result<ResolutionValue, ExecutionFactError> {
    Ok(ResolutionValue::CatalogRef {
        catalog_id: "iteron://tunables/catalogs/agent_catalog-v1".into(),
        digest_sha256: identity.digest_sha256.clone(),
        entry_count: u64::try_from(identity.entry_count)
            .map_err(|_| ExecutionFactError::IntegerOverflow("agent_catalog"))?,
        canonical_bytes: u64::try_from(identity.canonical_bytes)
            .map_err(|_| ExecutionFactError::IntegerOverflow("agent_catalog"))?,
    })
}

fn attest_literal_owner(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ExecutionFactsReport,
    family_id: &'static str,
    owner: ResolutionValue,
) -> Result<(), ExecutionFactError> {
    builder.attest_literal_owner(family_id, owner)?;
    report.mark(family_id, FactStage::Default);
    Ok(())
}

fn owned_literal(value: TunableValue) -> ResolutionValue {
    match value {
        TunableValue::Boolean { value } => ResolutionValue::Boolean { value },
        TunableValue::Integer { value } => ResolutionValue::Integer { value },
        TunableValue::Decimal { value } => ResolutionValue::Decimal { value },
        TunableValue::Text { value } => text(value),
        TunableValue::Enum { value } => en(value),
        TunableValue::List { items } => ResolutionValue::List {
            items: items.iter().copied().map(owned_literal).collect(),
        },
        TunableValue::Map { entries } => ResolutionValue::Map {
            entries: entries
                .iter()
                .map(|entry| (entry.name.to_owned(), owned_literal(entry.value)))
                .collect(),
        },
        TunableValue::Object { fields } => ResolutionValue::Object {
            fields: fields
                .iter()
                .map(|field| (field.name.to_owned(), owned_literal(field.value)))
                .collect(),
        },
    }
}

pub(super) fn hook_catalog_value(
    identity: &crate::runtime::hooks::HookCatalogIdentity,
) -> Result<ResolutionValue, ExecutionFactError> {
    Ok(ResolutionValue::CatalogRef {
        catalog_id: "iteron://tunables/catalogs/hooks_map-v1".into(),
        digest_sha256: identity.digest_sha256.clone(),
        entry_count: u64::try_from(identity.entry_count)
            .map_err(|_| ExecutionFactError::IntegerOverflow("hooks_map"))?,
        canonical_bytes: u64::try_from(identity.canonical_bytes)
            .map_err(|_| ExecutionFactError::IntegerOverflow("hooks_map"))?,
    })
}

pub(super) fn workflow_graph_value(
    identity: &iteron_workflow::WorkflowGraphRuntimeIdentity,
) -> Result<ResolutionValue, ExecutionFactError> {
    Ok(ResolutionValue::CatalogRef {
        catalog_id: "iteron://tunables/catalogs/workflow_graph-v1".into(),
        digest_sha256: identity.digest_sha256.clone(),
        entry_count: u64::try_from(identity.entry_count)
            .map_err(|_| ExecutionFactError::IntegerOverflow("workflow_graph"))?,
        canonical_bytes: u64::try_from(identity.canonical_bytes)
            .map_err(|_| ExecutionFactError::IntegerOverflow("workflow_graph"))?,
    })
}

pub(super) fn environment_snapshot_value(
    identity: &iteron_protocol::EnvironmentSnapshotIdentity,
) -> Result<ResolutionValue, ExecutionFactError> {
    Ok(object([
        ("present", boolv(identity.present)),
        ("digest_sha256", text(&identity.digest_sha256)),
        (
            "canonical_bytes",
            int(i64u(identity.canonical_bytes, "environment_snapshot")?),
        ),
        (
            "trust",
            en(match identity.trust {
                iteron_protocol::Trust::Untrusted => "untrusted",
                iteron_protocol::Trust::Workspace => "workspace",
                iteron_protocol::Trust::Trusted => "trusted",
            }),
        ),
    ]))
}

pub(super) fn capability_list(capabilities: CapabilitySet) -> ResolutionValue {
    ResolutionValue::List {
        items: capability_values(capabilities),
    }
}

pub(super) fn capability_values(capabilities: CapabilitySet) -> Vec<ResolutionValue> {
    capabilities
        .iter()
        .map(|capability| {
            text(match capability {
                Capability::ReadOnly => "read_only",
                Capability::ReversibleLocal => "reversible_local",
                Capability::CodeExecuting => "code_executing",
                Capability::TrustMutating => "trust_mutating",
                Capability::IrreversibleExternal => "irreversible_external",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multimodal_registry_literal_is_the_exact_rejecting_owner() {
        let owner =
            multimodal_decode_envelope_value(crate::image_input::multimodal_decode_envelope())
                .unwrap();
        let literal = iteron_tunables::families()
            .iter()
            .find(|family| family.id == "multimodal_input_admission_decode_envelope")
            .and_then(|family| family.default.value)
            .expect("family 68 must retain a fixed literal");
        let literal = owned_literal(literal);
        assert_eq!(owner, literal);
    }
}

impl ExecutionFactsInput<'_> {
    fn inventory_web_search(&self) -> bool {
        self.registry
            .specs()
            .iter()
            .any(|spec| spec.name == "web_search")
    }

    pub(super) fn inherited_effort_domain(&self) -> Vec<ResolutionValue> {
        if self.model_capabilities.semantic_effort == Some(true) {
            Effort::ALL
                .into_iter()
                .map(|effort| en(effort.label()))
                .collect()
        } else {
            vec![en(self.effort.label())]
        }
    }
}
