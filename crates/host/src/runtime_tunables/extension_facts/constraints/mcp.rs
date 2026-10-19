use super::{add_domain, add_upper, gap_constraint, missing_authority};
use crate::runtime_tunables::extension_facts::value::{en, int};
use crate::runtime_tunables::extension_facts::{
    ExtensionFactError, ExtensionFactsInput, ExtensionFactsReport, ExtensionGapReason, GapImpact,
};
use iteron_tunables::{ExternalCeiling, RuntimeResolutionBuilder};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    if !input.configured_mcp.is_empty() {
        match input.authorities.operator_mcp_transports {
            Some(transports) => add_domain(
                builder,
                report,
                147,
                "mcp_transport_selection",
                "$",
                ExternalCeiling::OperatorAuthority,
                [crate::runtime_tunables::extension_facts::value::list(
                    transports.iter().map(|transport| {
                        en(crate::runtime_tunables::extension_facts::value::transport(
                            *transport,
                        ))
                    }),
                )],
            )?,
            None => missing_authority(
                report,
                147,
                "mcp_transport_selection",
                "$",
                ExternalCeiling::OperatorAuthority,
            ),
        }
    }

    if input.budget.max_wall_secs == 0 {
        add_upper(
            builder,
            report,
            149,
            "mcp_reconnect_backoff",
            "cap_milliseconds",
            ExternalCeiling::ParentWall,
            int(0),
        )?;
        for (ordinal, family) in [
            (150, "per_server_startup_deadline"),
            (151, "per_tool_mcp_deadline"),
        ] {
            for field in ["stdio_milliseconds", "http_milliseconds"] {
                gap_constraint(
                    report,
                    ordinal,
                    family,
                    field,
                    ExternalCeiling::ParentWall,
                    ExtensionGapReason::ExternalCeilingBelowSchemaMinimum,
                    GapImpact::Blocking,
                );
            }
        }
    } else {
        let wall_ms = input
            .budget
            .max_wall_secs
            .saturating_mul(1_000)
            .min(86_400_000);
        add_upper(
            builder,
            report,
            149,
            "mcp_reconnect_backoff",
            "cap_milliseconds",
            ExternalCeiling::ParentWall,
            int(crate::runtime_tunables::extension_facts::value::i64v(
                wall_ms.min(iteron_mcp::reconnect::MAX_RECONNECT_CAP_MS),
                "mcp_reconnect_backoff",
            )?),
        )?;
        for (ordinal, family) in [
            (150, "per_server_startup_deadline"),
            (151, "per_tool_mcp_deadline"),
        ] {
            for field in ["stdio_milliseconds", "http_milliseconds"] {
                add_upper(
                    builder,
                    report,
                    ordinal,
                    family,
                    field,
                    ExternalCeiling::ParentWall,
                    int(crate::runtime_tunables::extension_facts::value::i64v(
                        wall_ms, family,
                    )?),
                )?;
            }
        }
    }

    if input
        .configured_mcp
        .iter()
        .any(|server| server.oauth.is_some())
    {
        match input.authorities.operator_oauth_modes {
            Some(modes) => add_domain(
                builder,
                report,
                153,
                "oauth_auth_lifecycle_policy",
                "credential_mode",
                ExternalCeiling::OperatorAuthority,
                modes.iter().map(|mode| {
                    en(crate::runtime_tunables::extension_facts::value::oauth_mode(
                        *mode,
                    ))
                }),
            )?,
            None => missing_authority(
                report,
                153,
                "oauth_auth_lifecycle_policy",
                "credential_mode",
                ExternalCeiling::OperatorAuthority,
            ),
        }
    }

    add_upper(
        builder,
        report,
        156,
        "http_pool_keepalive_idle_policy",
        "pool_idle_seconds",
        ExternalCeiling::ParentWall,
        int(crate::runtime_tunables::extension_facts::value::i64v(
            input.budget.max_wall_secs.min(86_400),
            "http_pool_keepalive_idle_policy",
        )?),
    )?;
    Ok(())
}
