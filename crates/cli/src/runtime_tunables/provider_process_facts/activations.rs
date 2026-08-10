use super::{
    FactGapReason, FactLayer, ProviderProcessFactError, ProviderProcessFactGap,
    ProviderProcessFactsInput, ProviderProcessFactsReport, VerificationOwnerFacts,
    owner::OwnerSnapshot,
};
use core_tunables::{CapabilityRequirement, RuntimeResolutionBuilder};

struct Inactive {
    ordinal: u16,
    family: &'static str,
    seam: &'static str,
    reason: FactGapReason,
}

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let static_inactive = [
        Inactive {
            ordinal: 93,
            family: "role_specific_model_map",
            seam: "crates/cli/src/runtime/workflow_spawner.rs",
            reason: FactGapReason::OwnerGetterMissing,
        },
        Inactive {
            ordinal: 113,
            family: "process_cwd_continuity",
            seam: "crates/tools/src/shell.rs",
            // The process owner uses job-scoped roots; the registry literal says session scope.
            reason: FactGapReason::OwnerSchemaMismatch,
        },
        Inactive {
            ordinal: 114,
            family: "child_process_environment_reuse",
            seam: "crates/sandbox/src/lib.rs",
            reason: FactGapReason::OwnerGetterMissing,
        },
        Inactive {
            ordinal: 122,
            family: "tool_result_cache_ttl",
            seam: "crates/tools/src/lib.rs",
            reason: FactGapReason::OwnerGetterMissing,
        },
        Inactive {
            ordinal: 124,
            family: "incremental_versus_full_verification",
            seam: "crates/verify/src/strategy.rs",
            reason: FactGapReason::OwnerSchemaMismatch,
        },
        Inactive {
            ordinal: 129,
            family: "workspace_checkpoint_cadence",
            seam: "crates/cli/src/runtime.rs",
            reason: FactGapReason::OwnerGetterMissing,
        },
        Inactive {
            ordinal: 130,
            family: "selective_restore_scope",
            seam: "crates/record/src/checkpoint.rs",
            reason: FactGapReason::OwnerSchemaMismatch,
        },
        Inactive {
            ordinal: 131,
            family: "verification_quorum_consensus",
            seam: "crates/verify/src/strategy.rs",
            reason: FactGapReason::OwnerSchemaMismatch,
        },
    ];
    for item in static_inactive {
        inactive(builder, owner, report, item)?;
    }

    for family in [
        "model_fallback_chain",
        "failover_eligible_error_taxonomy",
        "route_quality_cost_latency_objective_weights",
        "provider_health_circuit_breaker_state_policy",
        "hedged_request_policy",
    ] {
        active(
            builder,
            owner,
            report,
            family,
            "crates/provider/src/governor.rs",
        )?;
    }
    for family in ["provider_service_tier", "response_verbosity"] {
        active(
            builder,
            owner,
            report,
            family,
            "crates/provider/src/controls.rs",
        )?;
    }

    add_context_reserve_activation(builder, input, owner, report)?;
    add_context_budget_activations(builder, input, owner, report)?;
    active(
        builder,
        owner,
        report,
        "tool_output_spill_to_disk_policy",
        "crates/cli/src/runtime/tool_output_spill.rs",
    )?;
    for family in [
        "compaction_cooldown_hysteresis",
        "multi_stage_summary_topology",
    ] {
        active(builder, owner, report, family, "crates/ctx/src/compact.rs")?;
    }
    add_binary_routing_activation(builder, input, owner, report)?;
    add_flaky_activation(builder, input, owner, report)?;
    Ok(())
}

fn add_context_budget_activations(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let window_known = input
        .model_capabilities
        .context_window_tokens
        .is_some_and(|window| window > 0);
    for (ordinal, family, seam) in [
        (97, "system_prefix_budget", "crates/ctx/src/instructions.rs"),
        (
            98,
            "conversation_history_budget",
            "crates/ctx/src/compact.rs",
        ),
        (
            99,
            "tool_result_history_budget",
            "crates/cli/src/runtime.rs",
        ),
    ] {
        if window_known {
            active(builder, owner, report, family, seam)?;
        } else {
            inactive(
                builder,
                owner,
                report,
                Inactive {
                    ordinal,
                    family,
                    seam,
                    reason: FactGapReason::RequiredOwnerFieldUnknown,
                },
            )?;
        }
    }
    if window_known && input.model_capabilities.image_input == Some(true) {
        active(
            builder,
            owner,
            report,
            "multimodal_token_budget",
            "crates/cli/src/image_input.rs",
        )?;
    } else {
        inactive(
            builder,
            owner,
            report,
            Inactive {
                ordinal: 100,
                family: "multimodal_token_budget",
                seam: "crates/cli/src/image_input.rs",
                reason: if window_known {
                    FactGapReason::CapabilityNotAttested
                } else {
                    FactGapReason::RequiredOwnerFieldUnknown
                },
            },
        )?;
    }
    if window_known && owner.lsp_surface {
        active(
            builder,
            owner,
            report,
            "lsp_result_context_budget",
            "crates/ctx/src/compact.rs",
        )?;
    } else {
        inactive(
            builder,
            owner,
            report,
            Inactive {
                ordinal: 121,
                family: "lsp_result_context_budget",
                seam: "crates/ctx/src/compact.rs",
                reason: if owner.lsp_surface {
                    FactGapReason::RequiredOwnerFieldUnknown
                } else {
                    FactGapReason::CapabilityNotAttested
                },
            },
        )?;
    }
    Ok(())
}

fn add_context_reserve_activation(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let complete_partial_seam = input
        .model_capabilities
        .context_window_tokens
        .is_some_and(|tokens| tokens > 0)
        && input.model_capabilities.max_output_tokens.is_some()
        && input
            .route
            .capabilities
            .contains(&CapabilityRequirement::ProviderModelMetadata);
    if complete_partial_seam {
        active(
            builder,
            owner,
            report,
            "context_window_override_reserve",
            "crates/ctx/src/compact.rs",
        )
    } else {
        inactive(
            builder,
            owner,
            report,
            Inactive {
                ordinal: 96,
                family: "context_window_override_reserve",
                seam: "crates/ctx/src/compact.rs",
                reason: FactGapReason::RequiredOwnerFieldUnknown,
            },
        )
    }
}

fn add_binary_routing_activation(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let reason = if input
        .route
        .capabilities
        .contains(&CapabilityRequirement::ProviderMultimodal)
    {
        // Image decoding is present, but no typed mime->inspector table exists.
        FactGapReason::OwnerSchemaMismatch
    } else {
        FactGapReason::CapabilityNotAttested
    };
    inactive(
        builder,
        owner,
        report,
        Inactive {
            ordinal: 118,
            family: "binary_media_inspection_routing",
            seam: "crates/cli/src/image_input.rs",
            reason,
        },
    )
}

fn add_flaky_activation(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    match input.verification {
        VerificationOwnerFacts::Configured { .. } => active(
            builder,
            owner,
            report,
            "flaky_test_detection_quarantine",
            "crates/verify/src/strategy.rs",
        ),
        VerificationOwnerFacts::Disabled => inactive(
            builder,
            owner,
            report,
            Inactive {
                ordinal: 125,
                family: "flaky_test_detection_quarantine",
                seam: "crates/verify/src/strategy.rs",
                reason: FactGapReason::ExplicitlyDisabled,
            },
        ),
        VerificationOwnerFacts::GetterUnavailable => inactive(
            builder,
            owner,
            report,
            Inactive {
                ordinal: 125,
                family: "flaky_test_detection_quarantine",
                seam: "crates/verify/src/strategy.rs",
                reason: FactGapReason::OwnerGetterMissing,
            },
        ),
    }
}

fn active(
    builder: &mut RuntimeResolutionBuilder,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
    family: &'static str,
    seam: &'static str,
) -> Result<(), ProviderProcessFactError> {
    builder.activate(family, seam, true, owner.digest_for(family, "active")?)?;
    report.active_families.push(family);
    Ok(())
}

fn inactive(
    builder: &mut RuntimeResolutionBuilder,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
    item: Inactive,
) -> Result<(), ProviderProcessFactError> {
    builder.activate(
        item.family,
        item.seam,
        false,
        owner.digest_for(item.family, item.reason.code())?,
    )?;
    report.inactive_families.push(item.family);
    report.push_gap(ProviderProcessFactGap::new(
        item.ordinal,
        item.family,
        FactLayer::Activation,
        item.reason,
    ));
    Ok(())
}
