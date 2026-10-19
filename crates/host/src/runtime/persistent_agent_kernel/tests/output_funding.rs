//! Actual signed wallet -> context cap -> native prepared manifest -> WAL/audit/usage journey.
use super::cold_cohort::{config, make_main};
use super::{Arc, ProviderFixture, Workspace};
use iteron_protocol::{EventKind, Outcome, RunId, TokenRateCard};
#[tokio::test]
async fn finite_small_wallet_changes_the_real_native_request_not_only_a_quote() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let mut agent = make_main(
        &workspace,
        &RunId("small-wallet-main".into()),
        provider.clone(),
        false,
    );
    let route = agent.provider_selection.selected().unwrap().route.clone();
    let key = [51; 32];
    let signed = iteron_obs::sign_rate_card(
        iteron_protocol::RateCard {
            version: iteron_protocol::PricingVersion::V1,
            route,
            provenance: "actual-small-wallet-fixture".into(),
            issued_at_unix_secs: 1,
            expires_at_unix_secs: u64::MAX,
            rates: TokenRateCard {
                input_microusd_per_million: 100,
                output_microusd_per_million: 1000,
                cache_creation_microusd_per_million: 0,
                cache_read_microusd_per_million: 0,
                thinking_microusd_per_million: 0,
            },
        },
        "fixture-pricing",
        key,
    )
    .unwrap();
    agent.set_pricing_port(Arc::new(
        iteron_obs::HmacPricingAuthority::new(vec![(
            signed,
            iteron_obs::HmacPricingKey::from_bytes(key),
        )])
        .unwrap(),
    ));
    assert!(agent.bind_selected_rate_card().unwrap());
    agent.budget.max_usd = Some(15.0 / 1_000_000.0);
    agent.model_max_output_tokens = Some(8192);
    // Preserve zero explicit thinking, so adapter normalization does not require more output.
    agent.effort = iteron_protocol::Effort::Low;
    let mut budget = config();
    budget.root_budget.cost_microusd = 15;
    agent.enable_persistent_agents(budget, 2).unwrap();
    assert_eq!(
        agent.run("short actual native request").await.unwrap(),
        Outcome::Done
    );
    assert_eq!(
        provider.requests.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(&*provider.serialized_caps.lock().unwrap(), &[5000]);
    let rows = iteron_record::replay(agent.rollout.path()).unwrap();
    let audit = rows
        .iter()
        .find_map(|row| match &row.kind {
            EventKind::EffectIntent {
                tool, arguments, ..
            } if tool == "provider" => Some(arguments),
            _ => None,
        })
        .unwrap();
    assert_eq!(audit["max_tokens"].as_u64(), Some(5000));
    assert_eq!(audit["requested_max_tokens"].as_u64(), Some(8192));
    let charged = agent
        .list_persistent_agents()
        .unwrap()
        .into_iter()
        .find(|view| view.agent_id.0 == 1)
        .unwrap();
    assert!(charged.usage.cost_microusd <= 15);
    assert_eq!(charged.reserved.cost_microusd, 0);
    assert!(
        !rows
            .iter()
            .any(|row| matches!(&row.kind,EventKind::EffectUnknown {tool,..} if tool=="provider"))
    );
}
