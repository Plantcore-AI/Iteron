use super::{add_domain, missing_authority};
use crate::runtime_tunables::extension_facts::value::en;
use crate::runtime_tunables::extension_facts::{
    ExtensionFactError, ExtensionFactsInput, ExtensionFactsReport, ExtensionGapReason, FactLayer,
    GapImpact,
};
use core_tunables::{ExternalCeiling, RuntimeResolutionBuilder};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    for (ceiling, profiles) in [
        (
            ExternalCeiling::OperatorAuthority,
            input.authorities.operator_session_profiles,
        ),
        (
            ExternalCeiling::TenantScope,
            input.authorities.tenant_session_profiles,
        ),
    ] {
        match profiles {
            Some(profiles) => add_domain(
                builder,
                report,
                159,
                "session_isolation_profile",
                "$",
                ceiling,
                profiles.iter().map(|profile| {
                    en(crate::runtime_tunables::extension_facts::value::session_profile(*profile))
                }),
            )?,
            None => missing_authority(report, 159, "session_isolation_profile", "$", ceiling),
        }
    }

    match input.authorities.benchmark_replay_policy {
        Some(policy) if policy.fail_closed => {
            crate::runtime_tunables::extension_facts::value::exact(
                builder,
                "replay_divergence_detection_policy",
                "on_divergence",
                ExternalCeiling::BenchmarkProtocol,
                en("fail_closed"),
            )?;
            report.mark(
                160,
                "replay_divergence_detection_policy",
                FactLayer::Constraint {
                    field: "on_divergence",
                    ceiling: ExternalCeiling::BenchmarkProtocol,
                },
            );
        }
        Some(_) => report.gap(
            160,
            "replay_divergence_detection_policy",
            FactLayer::Constraint {
                field: "on_divergence",
                ceiling: ExternalCeiling::BenchmarkProtocol,
            },
            ExtensionGapReason::OwnerSchemaMismatch,
            GapImpact::Blocking,
        ),
        None => missing_authority(
            report,
            160,
            "replay_divergence_detection_policy",
            "on_divergence",
            ExternalCeiling::BenchmarkProtocol,
        ),
    }
    Ok(())
}
