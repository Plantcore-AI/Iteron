//! Single typed non-registry adapter to the authoritative effect journal owner.
//! Typed disjoint writer/owner ports ensure no executor receives mutable Agent state.
use super::effect_descriptor::{KernelEffect, effect_class_label, effect_workspace};
use super::effect_journal_owner::EffectJournalOwner;
use iteron_kernel::{effect_class, effects};
use iteron_record::Rollout;

/// Dispatch one non-registry effect across the single boundary.
///
/// Every class that is not a registry tool call goes through here, which is what makes the boundary
/// test enforceable: there is exactly one place in the kernel that builds a
/// [`effects::BrokeredEffect`] for them, so "no call site bypasses the broker" is a property of one
/// function rather than a promise about thirty call sites.
///
/// It is a free function, not a method, for a load-bearing reason: the executor almost always needs
/// to borrow *some* part of the agent (`hooks`, `provider`, `verify` state) while the boundary needs
/// `&mut rollout` and the session effect journal owner. Taking the two ledgers explicitly lets the caller
/// destructure the agent into disjoint borrows, which a `&mut self` method could not.
///
/// Returning [`effects::EffectDisposition::Unknown`] from `execute` is not an error path. It is the
/// honest answer when a dispatch crossed the boundary and no terminal could be observed, and it is
/// what stops recovery from ever replaying it.
pub(super) async fn broker_kernel_effect<Execute, ExecuteFuture, T>(
    rollout: &mut Rollout,
    journal: &mut EffectJournalOwner,
    effect: KernelEffect<'_>,
    execute: Execute,
) -> Result<effects::BrokeredOutcome<T>, effects::BrokerError>
where
    Execute: FnOnce() -> ExecuteFuture,
    ExecuteFuture: std::future::Future<Output = effects::EffectDisposition<T>>,
{
    let KernelEffect {
        turn,
        class,
        ordinal,
        capability,
        audit_arguments,
        workspace,
    } = effect;
    let brokered = effects::BrokeredEffect {
        turn,
        effect_id: effect_class::effect_id(turn, class, ordinal),
        tool_use_id: effect_class::harness_correlation_id(turn, class, ordinal),
        kind: effect_class_label(class).to_string(),
        capability,
        audit_arguments,
        workspace: effect_workspace(workspace),
        provider_route_attempt: None,
    };
    journal.broker(rollout, brokered, execute).await
}
