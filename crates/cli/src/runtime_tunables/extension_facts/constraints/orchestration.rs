use super::{add_domain, add_lower, add_upper, missing_authority};
use crate::runtime_tunables::extension_facts::value::{en, int};
use crate::runtime_tunables::extension_facts::{
    ExtensionFactError, ExtensionFactsInput, ExtensionFactsReport,
};
use iteron_tunables::{ExternalCeiling, RuntimeResolutionBuilder};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    add_upper(
        builder,
        report,
        137,
        "spawn_depth_control",
        "$",
        ExternalCeiling::RunBudget,
        int(i64::from(input.budget.max_turns.min(64))),
    )?;

    match input.authorities.run_session_spawn_cap {
        Some(limit) if limit <= 100_000 => add_upper(
            builder,
            report,
            138,
            "per_session_spawn_cap",
            "$",
            ExternalCeiling::RunBudget,
            int(crate::runtime_tunables::extension_facts::value::i64u(
                limit,
                "per_session_spawn_cap",
            )?),
        )?,
        _ => missing_authority(
            report,
            138,
            "per_session_spawn_cap",
            "$",
            ExternalCeiling::RunBudget,
        ),
    }
    add_upper(
        builder,
        report,
        139,
        "task_priority_scheduling",
        "priority_levels",
        ExternalCeiling::RunBudget,
        int(crate::runtime_tunables::extension_facts::value::i64u(
            input.run_limits.max_agent_calls().min(256),
            "task_priority_scheduling",
        )?),
    )?;
    let sibling_cap = input
        .run_limits
        .max_agent_calls()
        .saturating_sub(1)
        .min(input.speculative_siblings.max_siblings());
    for ceiling in [ExternalCeiling::RunBudget, ExternalCeiling::ParentCost] {
        add_upper(
            builder,
            report,
            140,
            "speculative_sibling_count",
            "$",
            ceiling,
            int(crate::runtime_tunables::extension_facts::value::i64u(
                sibling_cap,
                "speculative_sibling_count",
            )?),
        )?;
    }
    if input.budget.max_wall_secs == 0 {
        missing_authority(
            report,
            141,
            "speculative_sibling_cancellation",
            "cleanup_timeout_seconds",
            ExternalCeiling::ParentWall,
        );
    } else {
        add_upper(
            builder,
            report,
            141,
            "speculative_sibling_cancellation",
            "cleanup_timeout_seconds",
            ExternalCeiling::ParentWall,
            int(crate::runtime_tunables::extension_facts::value::i64v(
                input.budget.max_wall_secs.min(3_600),
                "speculative_sibling_cancellation",
            )?),
        )?;
    }
    add_domain(
        builder,
        report,
        141,
        "speculative_sibling_cancellation",
        "winner_evidence",
        ExternalCeiling::VerificationFloor,
        [en("first_verified")],
    )?;

    match input.authorities.verification_minimum_evidence {
        Some(minimum) if (1..=1_024).contains(&minimum) => add_lower(
            builder,
            report,
            142,
            "early_stop_quorum_policy",
            "minimum_evidence",
            ExternalCeiling::VerificationFloor,
            int(crate::runtime_tunables::extension_facts::value::i64u(
                minimum,
                "early_stop_quorum_policy",
            )?),
        )?,
        _ => missing_authority(
            report,
            142,
            "early_stop_quorum_policy",
            "minimum_evidence",
            ExternalCeiling::VerificationFloor,
        ),
    }

    match input.authorities.operator_messaging_topologies {
        Some(topologies) => add_domain(
            builder,
            report,
            145,
            "inter_agent_messaging_topology",
            "$",
            ExternalCeiling::OperatorAuthority,
            topologies.iter().map(|topology| {
                en(crate::runtime_tunables::extension_facts::value::messaging(
                    *topology,
                ))
            }),
        )?,
        None => missing_authority(
            report,
            145,
            "inter_agent_messaging_topology",
            "$",
            ExternalCeiling::OperatorAuthority,
        ),
    }
    add_domain(
        builder,
        report,
        145,
        "inter_agent_messaging_topology",
        "$",
        ExternalCeiling::RunBudget,
        [en("parent_mediated")],
    )?;
    add_domain(
        builder,
        report,
        143,
        "writer_worktree_isolation_mode",
        "$",
        ExternalCeiling::OperatorAuthority,
        [crate::runtime_tunables::extension_facts::value::boolv(true)],
    )?;
    add_domain(
        builder,
        report,
        144,
        "merge_conflict_arbitration",
        "on_conflict",
        ExternalCeiling::OperatorAuthority,
        [en("reject")],
    )?;
    add_domain(
        builder,
        report,
        144,
        "merge_conflict_arbitration",
        "require_verification",
        ExternalCeiling::VerificationFloor,
        [crate::runtime_tunables::extension_facts::value::boolv(true)],
    )?;
    add_upper(
        builder,
        report,
        146,
        "task_retry_reassignment_policy",
        "max_attempts",
        ExternalCeiling::RunBudget,
        int(crate::runtime_tunables::extension_facts::value::i64u(
            input
                .run_limits
                .max_agent_calls()
                .min(iteron_workflow::MAX_TASK_ATTEMPTS),
            "task_retry_reassignment_policy",
        )?),
    )?;
    add_domain(
        builder,
        report,
        146,
        "task_retry_reassignment_policy",
        "on_failure",
        ExternalCeiling::OperatorAuthority,
        [en(input.task_retry.on_failure().label())],
    )?;
    Ok(())
}
