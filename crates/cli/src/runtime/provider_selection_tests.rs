use super::ProviderSelectionOwner;
use crate::runtime::provider_selection_journal::ProviderSelectionJournal;
use crate::runtime::{DurableAppendFault, KernelError};
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::Ledger;
use iteron_obs::pricing::{HmacPricingAuthority, HmacPricingKey, sign_rate_card};
use iteron_protocol::{
    EventKind, PricingRoute, PricingVersion, RateCard, RunId, TenantId, TokenRateCard, TurnId,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
use iteron_record::Rollout;
use std::path::PathBuf;
use std::sync::Arc;

struct NeverDispatched;
#[async_trait::async_trait]
impl Provider for NeverDispatched {
    fn provider_instance_id(&self) -> Option<&str> {
        Some("provider")
    }
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("selection/pricing must never dispatch a provider")
    }
}
fn route(model: &str) -> PricingRoute {
    PricingRoute {
        provider_id: "provider".into(),
        model_id: model.into(),
        catalog_digest: format!("sha256:{}", "a".repeat(64)),
        capability_digest: format!("sha256:{}", "b".repeat(64)),
    }
}
fn directory() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "iteron-selection-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn real_selection_barrier_preserves_old_epoch_on_failure_and_reopen() {
    let directory = directory();
    let run = RunId("selection".into());
    let mut rollout = Rollout::open(&directory, &run, TenantId::default()).unwrap();
    let mut owner = ProviderSelectionOwner::default();
    let provider: Arc<dyn Provider> = Arc::new(NeverDispatched);
    let signed = sign_rate_card(
        RateCard {
            version: PricingVersion::V1,
            route: route("old"),
            provenance: "trusted-test-manifest".into(),
            issued_at_unix_secs: 1,
            expires_at_unix_secs: 100,
            rates: TokenRateCard {
                input_microusd_per_million: 1,
                output_microusd_per_million: 1,
                cache_creation_microusd_per_million: 1,
                cache_read_microusd_per_million: 1,
                thinking_microusd_per_million: 1,
            },
        },
        "selection-test",
        [77; 32],
    )
    .unwrap();
    owner.set_pricing_port(Arc::new(
        HmacPricingAuthority::new(vec![(signed.clone(), HmacPricingKey::from_bytes([77; 32]))])
            .unwrap(),
    ));
    let mut ledger = Ledger::default();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut fault = None;
    {
        let mut journal = ProviderSelectionJournal {
            rollout: &mut rollout,
            ledger: &mut ledger,
            record_failed: &mut failed,
            diagnostics: &diagnostics,
            fault: &mut fault,
        };
        owner
            .select(provider.clone(), route("old"), TurnId(1), &mut journal)
            .unwrap();
        assert!(owner.bind_card(TurnId(1), 10, &mut journal).unwrap());
    }
    fault = Some(DurableAppendFault::ModelSelected);
    let result = owner.select(
        provider.clone(),
        route("new"),
        TurnId(2),
        &mut ProviderSelectionJournal {
            rollout: &mut rollout,
            ledger: &mut ledger,
            record_failed: &mut failed,
            diagnostics: &diagnostics,
            fault: &mut fault,
        },
    );
    assert!(matches!(result, Err(KernelError::Record(_))));
    assert!(failed);
    assert_eq!(owner.selected().unwrap().route.model_id, "old");
    assert_eq!(owner.card(), Some(&signed));
    let rows = iteron_record::replay(rollout.path()).unwrap();
    assert_eq!(
        rows.iter()
            .filter(|row| matches!(row.kind, EventKind::ModelSelected { .. }))
            .count(),
        1
    );
    drop(rollout);
    let restarted = Rollout::open_existing(&directory, &run, TenantId::default()).unwrap();
    let rows = iteron_record::replay(restarted.path()).unwrap();
    let mut recovered = ProviderSelectionOwner::default();
    recovered.adopt_verified(
        ProviderSelectionOwner::recover_verified(&rows).unwrap(),
        provider.clone(),
    );
    assert_eq!(recovered.selected().unwrap().route.model_id, "old");
    assert!(recovered.card().is_none());
    assert!(recovered.validate_live(&provider, "old").is_ok());
    let forged_provider: Arc<dyn Provider> = Arc::new(NeverDispatched);
    assert!(recovered.validate_live(&forged_provider, "old").is_err());
    drop(restarted);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn card_append_refusal_clears_rejected_binding_without_changing_selected_provider() {
    let directory = directory();
    let mut rollout =
        Rollout::open(&directory, &RunId("card".into()), TenantId::default()).unwrap();
    let provider: Arc<dyn Provider> = Arc::new(NeverDispatched);
    let mut owner = ProviderSelectionOwner::default();
    let signed = sign_rate_card(
        RateCard {
            version: PricingVersion::V1,
            route: route("model"),
            provenance: "trusted-test-manifest".into(),
            issued_at_unix_secs: 1,
            expires_at_unix_secs: 100,
            rates: TokenRateCard {
                input_microusd_per_million: 1,
                output_microusd_per_million: 1,
                cache_creation_microusd_per_million: 1,
                cache_read_microusd_per_million: 1,
                thinking_microusd_per_million: 1,
            },
        },
        "selection-test",
        [78; 32],
    )
    .unwrap();
    owner.set_pricing_port(Arc::new(
        HmacPricingAuthority::new(vec![(signed, HmacPricingKey::from_bytes([78; 32]))]).unwrap(),
    ));
    let mut ledger = Ledger::default();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut fault = None;
    {
        let mut journal = ProviderSelectionJournal {
            rollout: &mut rollout,
            ledger: &mut ledger,
            record_failed: &mut failed,
            diagnostics: &diagnostics,
            fault: &mut fault,
        };
        owner
            .select(provider.clone(), route("model"), TurnId(1), &mut journal)
            .unwrap();
        owner.bind_card(TurnId(1), 10, &mut journal).unwrap();
    }
    fault = Some(DurableAppendFault::RateCardBound);
    assert!(
        owner
            .bind_card(
                TurnId(2),
                10,
                &mut ProviderSelectionJournal {
                    rollout: &mut rollout,
                    ledger: &mut ledger,
                    record_failed: &mut failed,
                    diagnostics: &diagnostics,
                    fault: &mut fault
                }
            )
            .is_err()
    );
    assert!(failed);
    assert!(owner.card().is_none());
    assert!(owner.validate_live(&provider, "model").is_ok());
    assert_eq!(
        iteron_record::replay(rollout.path())
            .unwrap()
            .iter()
            .filter(|row| matches!(row.kind, EventKind::RateCardBound { .. }))
            .count(),
        1
    );
    drop(rollout);
    std::fs::remove_dir_all(directory).unwrap();
}
