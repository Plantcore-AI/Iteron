use super::{ProviderAttemptJournal, ProviderIntent};
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
use iteron_record::Rollout;
use std::path::PathBuf;

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
        audit: serde_json::json!({"route_id":"provider:model","model":"model","physical_attempt":1,"max_tokens":128}),
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
