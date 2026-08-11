//! Process-wide fixed authorities owned by provider, process, and verification runtimes.
//!
//! These values can be re-sampled without session, route, or budget context.  Families whose
//! physical value is narrowed by a parent wall deadline stay checkpoint-reconstructed and are
//! deliberately absent from this collector.

use super::ProviderProcessFactError;
use super::value::{boolv, en, int, list, object, text};
use crate::runtime_tunables::fixed_artifacts::FixedAuthoritySample;
use iteron_tunables::{FixedAuthorityId, ResolutionValue};

pub(crate) fn live_fixed_authority_samples()
-> Result<Vec<FixedAuthoritySample>, ProviderProcessFactError> {
    Ok(vec![
        FixedAuthoritySample {
            family: "auto_compaction_enable",
            authority: FixedAuthorityId::StrategyInvariant,
            value: auto_compaction_owner_value(),
        },
        FixedAuthoritySample {
            family: "process_signal_kill_escalation",
            authority: FixedAuthorityId::RuntimeInvariant,
            value: process_signal_kill_escalation_owner_value(),
        },
        FixedAuthoritySample {
            family: "effecting_tool_concurrency",
            authority: FixedAuthorityId::StrategyInvariant,
            value: effecting_tool_concurrency_owner_value()?,
        },
        FixedAuthoritySample {
            family: "write_set_conflict_admission",
            authority: FixedAuthorityId::StrategyInvariant,
            value: write_set_conflict_admission_owner_value(),
        },
        FixedAuthoritySample {
            family: "retry_eligibility_policy",
            authority: FixedAuthorityId::StrategyInvariant,
            value: retry_eligibility_owner_value(
                &iteron_verify::VerificationRuntimePolicy::default().retry,
            ),
        },
        FixedAuthoritySample {
            family: "recovery_escalation_policy",
            authority: FixedAuthorityId::StrategyInvariant,
            value: recovery_escalation_owner_value(),
        },
    ])
}

pub(super) fn auto_compaction_owner_value() -> ResolutionValue {
    boolv(iteron_ctx::CompactionPolicy::default().enabled)
}

pub(super) fn process_signal_kill_escalation_owner_value() -> ResolutionValue {
    let _owner = iteron_sandbox::process_signal_kill_escalation_policy();
    en(iteron_sandbox::ProcessSignalKillEscalationPolicy::ID)
}

pub(super) fn effecting_tool_concurrency_owner_value()
-> Result<ResolutionValue, ProviderProcessFactError> {
    let owner = crate::runtime::effecting_tool_admission_policy();
    Ok(int(super::value::i64z(
        owner.max_concurrency,
        "effecting_tool_concurrency",
    )?))
}

pub(super) fn write_set_conflict_admission_owner_value() -> ResolutionValue {
    let owner = crate::runtime::effecting_tool_admission_policy();
    object([
        ("declared_set_required", boolv(owner.declared_set_required)),
        ("overlap", en(owner.overlap)),
        ("unknown_set", en(owner.unknown_set)),
    ])
}

pub(super) fn retry_eligibility_owner_value(
    retry: &iteron_verify::VerificationRetryPolicy,
) -> ResolutionValue {
    object([
        (
            "eligible_classes",
            list(retry.eligible_classes.iter().map(|class| text(class.id()))),
        ),
        ("max_attempts", int(i64::from(retry.max_attempts))),
        (
            "unknown",
            en(match retry.unknown {
                iteron_verify::UnknownVerificationRetryAction::Stop => "stop",
                iteron_verify::UnknownVerificationRetryAction::Operator => "operator",
            }),
        ),
    ])
}

pub(super) fn recovery_escalation_owner_value() -> ResolutionValue {
    let _owner = iteron_verify::verification_recovery_escalation_policy();
    en(iteron_verify::VerificationRecoveryEscalationPolicy::ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_samples_are_exact_unique_and_exclude_parent_wall_derived_timeouts() {
        let samples = live_fixed_authority_samples().expect("typed fixed owners");
        let families = samples
            .iter()
            .map(|sample| sample.family)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(families.len(), samples.len());
        assert_eq!(
            families,
            std::collections::BTreeSet::from([
                "auto_compaction_enable",
                "process_signal_kill_escalation",
                "effecting_tool_concurrency",
                "write_set_conflict_admission",
                "retry_eligibility_policy",
                "recovery_escalation_policy",
            ])
        );
        for checkpoint_derived in [
            "provider_connect_tls_timeout",
            "provider_request_total_deadline",
            "stream_idle_watchdog",
            "http_pool_keepalive_idle_policy",
        ] {
            assert!(!families.contains(checkpoint_derived));
        }
    }
}
