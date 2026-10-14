//! Read-only projection of one exact physical terminal into the logical token ledger. It never
//! signs a new projection, charges money, guesses a winning request, or reads the current card.
use super::KernelError;
use super::provider_attempt_journal::ProviderLogicalUsageEvidence;
use super::provider_charge_evidence::{RouteChargeTruth, verified_charge};
use iteron_obs::PricingPort;
use iteron_protocol::{
    CostAttribution, CostProjection, ProviderRouteCostTruth, RunId, TenantId, TurnId, Usage,
};

pub(super) struct LogicalUsageScope<'a> {
    pub(super) tenant: &'a TenantId,
    pub(super) run: &'a RunId,
    pub(super) turn: TurnId,
    pub(super) attribution: &'a Option<CostAttribution>,
}

pub(super) fn exact_projection(
    evidence: &ProviderLogicalUsageEvidence,
    scope: LogicalUsageScope<'_>,
    usage: Usage,
    pricing: Option<&dyn PricingPort>,
) -> Result<Option<CostProjection>, KernelError> {
    let ProviderLogicalUsageEvidence::Single(receipt) = evidence else {
        // Aggregated hedge tokens or recovered semantic text cannot identify one physical charge.
        return Ok(None);
    };
    if receipt.turn() != scope.turn {
        return Err(KernelError::PricingLedger(
            "logical usage receipt belongs to another turn",
        ));
    }
    let accounting = receipt.accounting();
    let truth = verified_charge(
        accounting,
        scope.tenant,
        scope.run,
        scope.turn,
        Some(scope.attribution),
        pricing,
    )?;
    if !matches!(truth, RouteChargeTruth::Known(_)) {
        return Ok(None);
    }
    let ProviderRouteCostTruth::Known {
        projection: Some(projection),
        ..
    } = &accounting.cost
    else {
        return Err(KernelError::PricingLedger(
            "known physical receipt lost its projection",
        ));
    };
    if projection.usage != usage
        || receipt.pricing_at_unix_secs() != Some(projection.projected_at_unix_secs)
    {
        return Err(KernelError::PricingLedger(
            "logical usage differs from its sealed physical terminal",
        ));
    }
    // The opaque receipt's source is the actual durable intent sequence retained by the journal.
    // No public timestamp/counter/body can construct this proof.
    let _source = receipt.intent_sequence();
    Ok(Some(projection.as_ref().clone()))
}

#[cfg(all(test, unix))]
#[path = "provider_logical_usage_tests.rs"]
pub(super) mod tests;
