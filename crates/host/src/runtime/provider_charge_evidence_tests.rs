use super::route_accounting_id;
use iteron_protocol::{
    ProviderRouteAttemptAccounting, ProviderRouteAttemptAccountingVersion, ProviderRouteCostTruth,
    ProviderRouteCostUnknownReason, ProviderRouteUsageTruth, ProviderRouteUsageUnknownReason,
};

#[test]
fn unknown_cost_is_never_encoded_as_zero() {
    let receipt = ProviderRouteAttemptAccounting {
        version: ProviderRouteAttemptAccountingVersion::V1,
        route_id: route_accounting_id("provider:model"),
        physical_attempt: 1,
        max_cost_reservation_microusd: None,
        usage: ProviderRouteUsageTruth::Unknown {
            reason: ProviderRouteUsageUnknownReason::ProvenFailureWithoutUsage,
        },
        cost: ProviderRouteCostTruth::Unknown {
            reason: ProviderRouteCostUnknownReason::ProvenFailureWithoutBillingEvidence,
        },
    };
    let value = serde_json::to_value(receipt).expect("serialize typed route receipt");
    assert_eq!(value["cost"]["state"], "unknown");
    assert!(value["cost"].get("amount_microusd").is_none());
}
