use super::{ProviderAttemptJournal, ProviderIntent, ProviderObservedAttempt};
use crate::runtime::effect_journal_owner::{EffectJournalOwner, UnknownCause};
use crate::runtime::provider_charge_evidence::not_dispatched_accounting;
use crate::runtime::provider_financial_context::{
    ProviderFinancialContext, ProviderFinancialOwners, ProviderFinancialScope,
    ProviderPricingEvidence,
};
use crate::runtime::{DurableAppendFault, KernelError};
use iteron_agents::ControllerError;
use iteron_kernel::{diagnostics::DiagnosticEmitter, effects};
use iteron_obs::Ledger;
use iteron_protocol::{Capability, EventKind, RunId, TenantId, TurnId};
use iteron_provider::UsageReport;
use iteron_record::Rollout;
use std::path::PathBuf;

#[tokio::test]
async fn controller_query_fault_after_actual_provider_call_preserves_sealed_terminal_on_reopen() {
    use crate::runtime::persistent_agents::{
        RuntimeProviderBudgetAdmission, RuntimeProviderBudgetPort,
    };
    use crate::runtime::provider_transport_attempt::{
        ProviderCancellation, execute_admitted_provider_turn_observed,
    };
    use iteron_agents::AgentProviderBudgetTerminal;
    use iteron_obs::pricing::{HmacPricingAuthority, HmacPricingKey, sign_rate_card};
    use iteron_protocol::{
        Block, PricingRoute, PricingVersion, ProviderRouteAttemptIdentity, ProviderRouteUsageTruth,
        RateCard, StopReason, TokenRateCard, Usage,
    };
    use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};

    struct FaultPort {
        fault: AtomicBool,
        queries: AtomicUsize,
        terminals: AtomicUsize,
        admission: Mutex<Option<RuntimeProviderBudgetAdmission>>,
        path: PathBuf,
    }
    impl RuntimeProviderBudgetPort for FaultPort {
        fn bind(&self, _: &str) -> Result<(), ControllerError> {
            Ok(())
        }
        fn reserve(
            &self,
            admission: RuntimeProviderBudgetAdmission,
        ) -> Result<(), ControllerError> {
            *self.admission.lock().unwrap() = Some(admission);
            Ok(())
        }
        fn reservation(
            &self,
            _: &str,
            _: u32,
            _: &ProviderRouteAttemptIdentity,
        ) -> Result<Option<u64>, ControllerError> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            if self.fault.load(Ordering::SeqCst) {
                Err(ControllerError::RecoveryRequired)
            } else {
                Ok(self
                    .admission
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|admission| admission.max_cost_microusd))
            }
        }
        fn settle(
            &self,
            _: &str,
            effect: &str,
            route: &ProviderRouteAttemptIdentity,
            _: AgentProviderBudgetTerminal,
            _: &str,
        ) -> Result<(), ControllerError> {
            let rows = iteron_record::replay(&self.path).unwrap();
            assert!(rows.iter().any(|row| matches!(&row.kind, EventKind::EffectDone { id, provider_route_attempt: Some(accounting), .. }
                if id.0 == effect && accounting.physical_attempt == route.physical_attempt
                && matches!(accounting.usage, ProviderRouteUsageTruth::Known { .. }))));
            self.terminals.fetch_add(1, Ordering::SeqCst);
            Err(ControllerError::RecoveryRequired)
        }
    }
    struct ActualCall {
        port: Arc<FaultPort>,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl Provider for ActualCall {
        fn attempt_semantics(&self) -> iteron_provider::ProviderAttemptSemantics {
            iteron_provider::ProviderAttemptSemantics::Single
        }
        async fn turn(
            &self,
            _: &TurnRequest,
            _: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.port.fault.store(true, Ordering::SeqCst);
            Ok(TurnResult {
                blocks: vec![Block::Text {
                    text: "completed".into(),
                }],
                stop_reason: StopReason::EndTurn,
                usage: UsageReport::complete(Usage {
                    input: 2,
                    output: 3,
                    ..Usage::default()
                }),
            })
        }
    }
    let workspace = directory();
    let run = RunId("physical".into());
    let mut rollout = Rollout::open(&workspace, &run, TenantId::default()).unwrap();
    let port = Arc::new(FaultPort {
        fault: AtomicBool::new(false),
        queries: AtomicUsize::new(0),
        terminals: AtomicUsize::new(0),
        admission: Mutex::new(None),
        path: rollout.path().to_path_buf(),
    });
    let signed = sign_rate_card(
        RateCard {
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
        },
        "pricing-test",
        [35; 32],
    )
    .unwrap();
    let pricing = Arc::new(
        HmacPricingAuthority::new(vec![(signed.clone(), HmacPricingKey::from_bytes([35; 32]))])
            .unwrap(),
    );
    let make_financial = || {
        ProviderFinancialContext::new(
            ProviderFinancialScope {
                tenant: TenantId::default(),
                run_id: run.clone(),
                attribution: None,
            },
            ProviderPricingEvidence {
                port: Some(pricing.clone()),
                card: Some(signed.clone()),
                context_window: Some(16),
                usage_bounds: iteron_provider::ProviderUsageBoundSemantics::IndependentClasses,
            },
            ProviderFinancialOwners {
                usd: None,
                cohort: Ok(Some(port.clone())),
            },
        )
    };
    let mut effects = EffectJournalOwner::default();
    let mut ledger = Ledger::default();
    effects.guard_recovery(&mut rollout, &mut ledger).unwrap();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut fault = None;
    let ticket = ProviderAttemptJournal {
        rollout: &mut rollout,
        effects: &mut effects,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
        financial: make_financial(),
        pricing_now: 10,
        fault: &mut fault,
    }
    .open(&workspace, intent())
    .unwrap();
    let sealed = ticket.provider_route_attempt().unwrap().clone();
    assert_eq!(ticket.provider_pricing_at_unix_secs(), Some(10));
    let id = ticket.effect_id().clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let result = execute_admitted_provider_turn_observed(
        Arc::new(ActualCall {
            port: port.clone(),
            calls: calls.clone(),
        }),
        Instant::now() + Duration::from_secs(3),
        ProviderCancellation {
            interrupt: None,
            force_cancel: Arc::new(AtomicBool::new(false)),
            drain: Arc::new(AtomicBool::new(false)),
            attempt: None,
            allow_in_flight_past_deadline: false,
        },
        &TurnRequest {
            model: "model".into(),
            system: "system".into(),
            messages: vec![],
            input_images: vec![],
            tools: vec![].into(),
            max_tokens: 128,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: iteron_protocol::ReasoningEffort::Medium,
            controls: Default::default(),
        },
        &mut |_| {},
        None,
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        make_financial()
            .cohort_reservation(TurnId(1), "provider:model", 1)
            .is_err()
    );
    let queries = port.queries.load(Ordering::SeqCst);
    let settled = ProviderAttemptJournal {
        rollout: &mut rollout,
        effects: &mut effects,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
        financial: make_financial(),
        // The actual stream completed after the signed card expired. Settlement must retain
        // the authoritative admission time rather than consult the later terminal clock.
        pricing_now: 1_000,
        fault: &mut fault,
    }
    .settle_observed(
        ticket,
        ProviderObservedAttempt {
            route_id: "provider:model",
            result: &result,
        },
    );
    assert!(matches!(
        settled,
        Err(KernelError::AgentControl(ControllerError::RecoveryRequired))
    ));
    assert_eq!(port.queries.load(Ordering::SeqCst), queries);
    assert_eq!(port.terminals.load(Ordering::SeqCst), 1);
    assert!(!failed);
    drop(rollout);
    let mut restarted = Rollout::open_existing(&workspace, &run, TenantId::default()).unwrap();
    let rows = iteron_record::replay(restarted.path()).unwrap();
    assert!(rows.iter().any(|row| matches!(&row.kind, EventKind::EffectDone { id: actual, provider_route_attempt: Some(accounting), .. }
        if *actual == id && accounting.identity() == sealed && matches!(accounting.usage, ProviderRouteUsageTruth::Known { usage } if usage.input == 2 && usage.output == 3)
        && matches!(&accounting.cost, iteron_protocol::ProviderRouteCostTruth::Known { projection: Some(projection), .. } if projection.projected_at_unix_secs == 10))));
    let mut recovered = EffectJournalOwner::default();
    recovered
        .guard_recovery(&mut restarted, &mut Ledger::default())
        .unwrap();
    assert_eq!(
        iteron_record::replay(restarted.path()).unwrap().len(),
        rows.len()
    );
    drop(restarted);
    std::fs::remove_dir_all(workspace).unwrap();
}

fn directory() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "iteron-provider-journal-{}-{next}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn financial(unavailable: bool) -> ProviderFinancialContext {
    ProviderFinancialContext::new(
        ProviderFinancialScope {
            tenant: TenantId::default(),
            run_id: RunId("physical".into()),
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
            cohort: if unavailable {
                Err(ControllerError::RecoveryRequired)
            } else {
                Ok(None)
            },
        },
    )
}

fn intent() -> ProviderIntent {
    ProviderIntent {
        turn: TurnId(1),
        ordinal: 0,
        capability: Capability::IrreversibleExternal,
        audit: serde_json::json!({"route_id":"provider:model","model":"model","physical_attempt":1,"max_tokens":128,"provider_pricing_at_unix_secs":1}),
    }
}

#[test]
fn real_intent_fault_keeps_the_physical_record_empty_and_latches_failure() {
    let workspace = directory();
    let run = RunId("physical".into());
    let mut rollout = Rollout::open(&workspace, &run, TenantId::default()).unwrap();
    let mut effects = EffectJournalOwner::default();
    let mut ledger = Ledger::default();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut fault = Some(DurableAppendFault::EffectIntent);
    let before = iteron_record::replay(rollout.path()).unwrap().len();
    let result = ProviderAttemptJournal {
        rollout: &mut rollout,
        effects: &mut effects,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
        financial: financial(false),
        pricing_now: 10,
        fault: &mut fault,
    }
    .open(&workspace, intent());
    assert!(matches!(result, Err(KernelError::Record(_))));
    assert!(failed);
    assert!(fault.is_none());
    assert_eq!(iteron_record::replay(rollout.path()).unwrap().len(), before);
    drop(rollout);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn unavailable_downstream_finance_does_not_erase_the_actual_terminal_or_restart_proof() {
    let workspace = directory();
    let run = RunId("physical".into());
    let mut rollout = Rollout::open(&workspace, &run, TenantId::default()).unwrap();
    let mut effects = EffectJournalOwner::default();
    let mut ledger = Ledger::default();
    effects.guard_recovery(&mut rollout, &mut ledger).unwrap();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut fault = None;
    let ticket = ProviderAttemptJournal {
        rollout: &mut rollout,
        effects: &mut effects,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
        financial: financial(false),
        pricing_now: 10,
        fault: &mut fault,
    }
    .open(&workspace, intent())
    .unwrap();
    let id = ticket.effect_id().clone();
    let accounting = not_dispatched_accounting("provider:model", 1).unwrap();
    let result = ProviderAttemptJournal {
        rollout: &mut rollout,
        effects: &mut effects,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
        financial: financial(true),
        pricing_now: 10,
        fault: &mut fault,
    }
    .settle(
        ticket,
        effects::Settlement::Definite(EventKind::EffectFailed {
            id: id.clone(),
            tool: "provider".into(),
            reason: "actual predispatch refusal".into(),
            duration_ms: None,
            provider_route_attempt: Some(accounting),
        }),
        UnknownCause::Unobserved,
    );
    assert!(matches!(
        result,
        Err(KernelError::AgentControl(ControllerError::RecoveryRequired))
    ));
    assert!(!failed);
    assert!(effects.parent_settlement_known());
    drop(rollout);
    let mut restarted = Rollout::open_existing(&workspace, &run, TenantId::default()).unwrap();
    let before = iteron_record::replay(restarted.path()).unwrap();
    assert_eq!(before.iter().filter(|row| matches!(&row.kind, EventKind::EffectFailed { id: actual, .. } if *actual == id)).count(), 1);
    let mut recovered = EffectJournalOwner::default();
    recovered
        .guard_recovery(&mut restarted, &mut Ledger::default())
        .unwrap();
    assert!(recovered.parent_settlement_known());
    assert_eq!(
        iteron_record::replay(restarted.path()).unwrap().len(),
        before.len()
    );
    drop(restarted);
    std::fs::remove_dir_all(workspace).unwrap();
}
