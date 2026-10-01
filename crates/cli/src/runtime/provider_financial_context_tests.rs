use super::{
    ProviderFinancialContext, ProviderFinancialOwners, ProviderFinancialScope,
    ProviderPricingEvidence,
};
use crate::runtime::KernelError;
use crate::runtime::pricing::SharedUsdBudget;
use iteron_obs::pricing::{HmacPricingAuthority, HmacPricingKey, sign_rate_card};
use iteron_protocol::{
    Block, PricingRoute, PricingVersion, ProviderRouteCostTruth, ProviderRouteUsageTruth, RateCard,
    RunId, StopReason, TenantId, TokenRateCard, TurnId, Usage, UsageReport,
};
use iteron_provider::{ProviderError, TurnResult};
use std::sync::Arc;

fn context(tenant: &str, budget: Arc<SharedUsdBudget>) -> ProviderFinancialContext {
    let card = RateCard {
        version: PricingVersion::V1,
        route: PricingRoute {
            provider_id: "provider".into(),
            model_id: "model".into(),
            catalog_digest: format!("sha256:{}", "a".repeat(64)),
            capability_digest: format!("sha256:{}", "b".repeat(64)),
        },
        provenance: "immutable-test-manifest".into(),
        issued_at_unix_secs: 1,
        expires_at_unix_secs: 100,
        rates: TokenRateCard {
            input_microusd_per_million: 1_000_000,
            output_microusd_per_million: 1_000_000,
            cache_creation_microusd_per_million: 1_000_000,
            cache_read_microusd_per_million: 1_000_000,
            thinking_microusd_per_million: 1_000_000,
        },
    };
    let key = [31; 32];
    let signed = sign_rate_card(card, "pricing-test", key).unwrap();
    let port =
        HmacPricingAuthority::new(vec![(signed.clone(), HmacPricingKey::from_bytes(key))]).unwrap();
    ProviderFinancialContext::new(
        ProviderFinancialScope {
            tenant: TenantId(tenant.into()),
            run_id: RunId("run".into()),
            attribution: None,
        },
        ProviderPricingEvidence {
            port: Some(Arc::new(port)),
            card: Some(signed),
            context_window: Some(16),
            usage_bounds: iteron_provider::ProviderUsageBoundSemantics::IndependentClasses,
        },
        ProviderFinancialOwners {
            usd: Some(budget),
            cohort: Ok(None),
        },
    )
}

fn known() -> Result<TurnResult, KernelError> {
    Ok(TurnResult {
        blocks: vec![Block::Text {
            text: "actual completed request".into(),
        }],
        stop_reason: StopReason::EndTurn,
        usage: UsageReport::complete(Usage {
            input: 2,
            output: 3,
            ..Usage::default()
        }),
    })
}

#[test]
fn exact_signed_attempt_is_charged_once_in_the_actual_shared_owner() {
    let budget = Arc::new(SharedUsdBudget::from_microusd(100));
    budget.reserve_provider_attempt(20).unwrap();
    let context = context("tenant", budget.clone());
    let accounting = context
        .route_attempt_accounting(TurnId(7), "provider:model", 41, &known(), 10)
        .unwrap();
    assert_eq!(accounting.max_cost_reservation_microusd, Some(20));
    context
        .commit_provider_route_charge(TurnId(7), &accounting)
        .unwrap();
    context
        .commit_provider_route_charge(TurnId(7), &accounting)
        .unwrap();
    assert_eq!(budget.spent_microusd(), 5);
    assert_eq!(budget.remaining_microusd().unwrap(), 95);
}

#[test]
fn signed_receipt_cannot_cross_the_authenticated_tenant_or_physical_attempt() {
    for wrong_tenant in [false, true] {
        let source_budget = Arc::new(SharedUsdBudget::from_microusd(100));
        let source = context("tenant", source_budget);
        let mut accounting = source
            .route_attempt_accounting(TurnId(7), "provider:model", 41, &known(), 10)
            .unwrap();
        let target_budget = Arc::new(SharedUsdBudget::from_microusd(100));
        target_budget.reserve_provider_attempt(20).unwrap();
        let target = context(
            if wrong_tenant { "other" } else { "tenant" },
            target_budget.clone(),
        );
        if !wrong_tenant {
            accounting.physical_attempt = 42;
        }
        assert!(
            target
                .commit_provider_route_charge(TurnId(7), &accounting)
                .is_err()
        );
        assert_eq!(target_budget.spent_microusd(), 0);
        assert!(target_budget.remaining_microusd().is_err());
    }
}

#[test]
fn exact_capture_refusal_releases_zero_while_unknown_keeps_the_real_reservation() {
    for local_refusal in [true, false] {
        let budget = Arc::new(SharedUsdBudget::from_microusd(100));
        budget.reserve_provider_attempt(20).unwrap();
        let context = context("tenant", budget.clone());
        let result = Err(KernelError::Provider(if local_refusal {
            ProviderError::RequestCaptureRefusedBeforeDispatch
        } else {
            ProviderError::DeadlineExceeded
        }));
        let accounting = context
            .route_attempt_accounting(TurnId(7), "provider:model", 41, &result, 10)
            .unwrap();
        if local_refusal {
            assert!(matches!(
                accounting.usage,
                ProviderRouteUsageTruth::NotDispatched
            ));
            assert!(matches!(
                accounting.cost,
                ProviderRouteCostTruth::NotDispatched
            ));
            context
                .commit_provider_route_charge(TurnId(7), &accounting)
                .unwrap();
            assert_eq!(budget.remaining_microusd().unwrap(), 100);
        } else {
            assert!(
                context
                    .commit_provider_route_charge(TurnId(7), &accounting)
                    .is_err()
            );
            assert_eq!(budget.active_reservation_microusd(), Some(20));
            assert!(budget.remaining_microusd().is_err());
        }
    }
}

#[test]
fn actual_agent_prompt_window_cannot_shrink_the_physical_financial_input_bound() {
    use crate::runtime::{Agent, gate_integration_tests};
    use iteron_provider::{OpenAiResponses, Provider};
    let root = gate_integration_tests::temp_ws("physical-input-vs-prompt-profile");
    let native = Arc::new(OpenAiResponses::new("unused-fixture".into(), None).unwrap());
    let physical = native.physical_input_token_ceiling("gpt-5.6").unwrap();
    let rollout = iteron_record::Rollout::open(
        &root.join(".iteron/runs"),
        &RunId("physical-input-profile".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        native,
        iteron_tools::Registry::read_only(&root).unwrap(),
        rollout,
        "gpt-5.6".into(),
        "fixture".into(),
        iteron_protocol::Budget::default(),
    );
    agent.model_context_window = Some(32);
    assert_eq!(agent.execution_context_window(), Some(32));
    assert_eq!(
        agent.provider_financial_context().context_window,
        Some(physical)
    );
    agent.model = "unknown-fixture-model".into();
    assert_eq!(agent.provider_financial_context().context_window, None);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn output_funding_authenticates_current_signature_scope_time_and_known_wallet() {
    let budget = Arc::new(SharedUsdBudget::from_microusd(55));
    let c = context("tenant", budget.clone());
    let funding = c.output_funding("provider:model", 2).unwrap().unwrap();
    assert_eq!(funding.input, 16);
    assert_eq!(funding.cost_microusd, 55);
    assert!(c.output_funding("foreign:model", 2).is_err());
    assert!(c.output_funding("provider:model", 100).is_err());
    let mut tampered = context("tenant", budget.clone());
    tampered
        .pricing
        .as_mut()
        .unwrap()
        .rate_card
        .rates
        .input_microusd_per_million = 0;
    assert!(tampered.output_funding("provider:model", 2).is_err());
    budget.mark_unknown();
    assert!(c.output_funding("provider:model", 2).is_err());
}

#[test]
fn physical_price_admission_rechecks_expiry_but_never_requotes_an_owned_reservation() {
    let budget = Arc::new(SharedUsdBudget::from_microusd(55));
    let context = context("tenant", budget.clone());
    budget.reserve_provider_attempt(55).unwrap();
    assert_eq!(budget.remaining_microusd().unwrap(), 0);
    assert!(
        context
            .validate_pricing_admission("provider:model", 2)
            .is_ok()
    );
    assert!(
        context
            .validate_pricing_admission("provider:model", 100)
            .is_err()
    );
    assert!(
        context
            .validate_pricing_admission("foreign:model", 2)
            .is_err()
    );
    assert_eq!(budget.active_reservation_microusd(), Some(55));
    assert_eq!(budget.remaining_microusd().unwrap(), 0);
}

#[test]
fn ordinary_price_admission_has_no_signed_card_or_input_proof_requirement() {
    let context = ProviderFinancialContext::new(
        ProviderFinancialScope {
            tenant: TenantId("tenant".into()),
            run_id: RunId("run".into()),
            attribution: None,
        },
        ProviderPricingEvidence {
            port: None,
            card: None,
            context_window: None,
            usage_bounds: iteron_provider::ProviderUsageBoundSemantics::IndependentClasses,
        },
        ProviderFinancialOwners {
            usd: None,
            cohort: Ok(None),
        },
    );
    assert!(
        context
            .validate_pricing_admission("ordinary:unknown-model", 0)
            .is_ok()
    );
}
