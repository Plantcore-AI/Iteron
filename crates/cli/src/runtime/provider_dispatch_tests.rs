use super::{
    ProviderAdmissionJournal, ProviderDispatchOwner, ProviderDispatchScope,
    ProviderObjectiveEvidence,
};
use crate::runtime::effect_journal_owner::EffectJournalOwner;
use crate::runtime::provider_attempt_journal::ProviderAttemptJournal;
use crate::runtime::provider_financial_context::{
    ProviderFinancialContext, ProviderFinancialOwners, ProviderFinancialScope,
    ProviderPricingEvidence,
};
use crate::runtime::provider_route_events::ProviderRouteEvents;
use crate::runtime::provider_route_turn::ProviderRouteTurn;
use crate::runtime::session_control::SessionControlState;
use crate::runtime::terminal_record::TerminalRecordOwner;
use crate::runtime::turn_activity::ActivitySink;
use crate::runtime::turn_publication::TurnPublicationOwner;
use crate::runtime::{DurableAppendFault, KernelError};
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::{Ledger, lifecycle::LifecycleCorrelation};
use iteron_protocol::{
    EventKind, ProviderRouteUsageTruth, ReasoningEffort, RunId, TenantId, TurnId,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
use iteron_record::Rollout;
use iteron_sched::BackoffPolicy;
use std::{path::PathBuf, sync::Arc, time::Duration};

struct AdmissionOnlyProvider;
#[async_trait::async_trait]
impl Provider for AdmissionOnlyProvider {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("admission owner must not execute a provider request");
    }
}

struct ExtensionLease(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for ExtensionLease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
struct AdmissionExtension {
    refuse: bool,
    active: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl crate::runtime::provider_extension::ProviderDispatchGate for AdmissionExtension {
    async fn enter_dispatch(
        &self,
    ) -> Result<Option<crate::runtime::provider_extension::ProviderExtensionPermit>, ()> {
        if self.refuse {
            return Err(());
        }
        self.active
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Ok(Some(
            crate::runtime::provider_extension::ProviderExtensionPermit::retain(ExtensionLease(
                self.active.clone(),
            )),
        ))
    }
}
impl crate::runtime::provider_extension::ProviderDispatchExtension for AdmissionExtension {
    fn terminal(&self) -> Option<crate::runtime::provider_extension::ProviderExtensionTerminal> {
        None
    }
    fn observe_physical_attempt(
        &mut self,
        _: TurnId,
        _: &iteron_protocol::ProviderRouteAttemptAccounting,
    ) -> Result<(), &'static str> {
        panic!("admission fixtures must not invent a physical terminal");
    }
}

#[tokio::test]
async fn extension_refusal_precedes_real_provider_intent() {
    let mut host = Harness::new();
    let extension = AdmissionExtension {
        refuse: true,
        active: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };
    let mut owner = host.owner();
    owner.scope.extension = Some(&extension);
    let refused = owner
        .initial(&mut route(), None, false, objective())
        .await
        .unwrap();
    assert!(matches!(
        refused,
        Some(KernelError::Provider(ProviderError::Interrupted))
    ));
    assert!(host.rows().iter().all(|row| !matches!(
        row.kind,
        EventKind::EffectIntent { .. } | EventKind::TurnStart
    )));
}

#[tokio::test]
async fn real_intent_refusal_releases_the_adapter_owned_lease() {
    let mut host = Harness::new();
    host.fault = Some(DurableAppendFault::EffectIntent);
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let extension = AdmissionExtension {
        refuse: false,
        active: active.clone(),
    };
    let mut owner = host.owner();
    owner.scope.extension = Some(&extension);
    assert!(
        owner
            .initial(&mut route(), None, false, objective())
            .await
            .is_err()
    );
    assert_eq!(active.load(std::sync::atomic::Ordering::Acquire), 0);
    assert!(
        host.rows()
            .iter()
            .all(|row| !matches!(row.kind, EventKind::EffectIntent { .. }))
    );
}
fn route() -> ProviderRouteTurn {
    ProviderRouteTurn::new(
        TurnRequest {
            model: "fixture".into(),
            system: "fixture".into(),
            messages: vec![],
            input_images: vec![],
            tools: vec![].into(),
            max_tokens: 128,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: ReasoningEffort::Low,
            controls: Default::default(),
        },
        128,
        Arc::new(AdmissionOnlyProvider),
        "fixture:fixture".into(),
        &[],
        BackoffPolicy {
            base_ms: 0,
            cap_ms: 0,
            max_attempts: 2,
        },
        Duration::from_secs(1),
    )
}
fn objective() -> ProviderObjectiveEvidence {
    ProviderObjectiveEvidence {
        score: None,
        digest: None,
    }
}
struct Harness {
    workspace: PathBuf,
    rollout: Rollout,
    effects: EffectJournalOwner,
    ledger: Ledger,
    failed: bool,
    fault: Option<DurableAppendFault>,
    diagnostics: DiagnosticEmitter,
    terminal: TerminalRecordOwner,
    publications: TurnPublicationOwner,
    controls: SessionControlState,
    events: ProviderRouteEvents,
}
impl Harness {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let workspace = std::env::temp_dir().join(format!(
            "iteron-provider-dispatch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&workspace).unwrap();
        let mut rollout =
            Rollout::open(&workspace, &RunId("admission".into()), TenantId::default()).unwrap();
        let mut effects = EffectJournalOwner::default();
        let mut ledger = Ledger::default();
        effects.guard_recovery(&mut rollout, &mut ledger).unwrap();
        let publications = TurnPublicationOwner::for_rollout(&rollout);
        Self {
            workspace,
            rollout,
            effects,
            ledger,
            failed: false,
            fault: None,
            diagnostics: DiagnosticEmitter::default(),
            terminal: TerminalRecordOwner::default(),
            publications,
            controls: SessionControlState::default(),
            events: ProviderRouteEvents {
                turn: TurnId(1),
                lifecycle: None,
                hooks: None,
                correlation: LifecycleCorrelation::default(),
                activity: ActivitySink::default(),
            },
        }
    }
    fn owner(&mut self) -> ProviderDispatchOwner<'_> {
        let financial = ProviderFinancialContext::new(
            ProviderFinancialScope {
                tenant: TenantId::default(),
                run_id: RunId("admission".into()),
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
        ProviderDispatchOwner {
            journal: ProviderAdmissionJournal {
                physical: ProviderAttemptJournal {
                    rollout: &mut self.rollout,
                    effects: &mut self.effects,
                    ledger: &mut self.ledger,
                    record_failed: &mut self.failed,
                    diagnostics: &self.diagnostics,
                    financial,
                    pricing_now: 10,
                    fault: &mut self.fault,
                },
                terminal: &mut self.terminal,
                policy: None,
                publications: &mut self.publications,
            },
            scope: ProviderDispatchScope {
                workspace: &self.workspace,
                extension: None,
                events: &self.events,
                control: &self.controls,
                deadline: None,
                pricing_now_unix_secs: Some(10),
            },
        }
    }
    fn rows(&self) -> Vec<iteron_protocol::Event> {
        iteron_record::replay(self.rollout.path()).unwrap()
    }
}

#[tokio::test]
async fn refused_real_intent_never_commits_logical_start() {
    let mut host = Harness::new();
    let mut route = route();
    host.fault = Some(DurableAppendFault::EffectIntent);
    assert!(
        host.owner()
            .initial(&mut route, None, false, objective())
            .await
            .is_err()
    );
    assert!(route.ticket().is_none());
    assert!(host.rows().iter().all(|row| !matches!(
        row.kind,
        EventKind::TurnStart | EventKind::EffectIntent { .. }
    )));
}

#[tokio::test]
async fn refused_logical_start_records_actual_zero_and_restart_keeps_identity() {
    let mut host = Harness::new();
    let mut route = route();
    host.fault = Some(DurableAppendFault::TurnStart);
    assert!(
        host.owner()
            .initial(&mut route, None, false, objective())
            .await
            .is_err()
    );
    assert!(route.ticket().is_none());
    let rows = host.rows();
    assert!(rows.iter().any(|row| matches!(&row.kind, EventKind::EffectIntent { provider_route_attempt: Some(identity), .. } if identity.physical_attempt == 1)));
    assert!(rows.iter().any(|row| matches!(&row.kind, EventKind::EffectFailed { provider_route_attempt: Some(accounting), .. } if accounting.physical_attempt == 1 && matches!(accounting.usage, ProviderRouteUsageTruth::NotDispatched))));
    assert!(
        rows.iter()
            .all(|row| !matches!(row.kind, EventKind::TurnStart))
    );
    // Open the actual durable prefix and recover its canonical provider ordinal. A refused
    // logical start still consumed a physical admission identity; it must never be reused.
    drop(host.rollout);
    let mut restarted = Rollout::open_existing(
        &host.workspace,
        &RunId("admission".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut recovered = EffectJournalOwner::default();
    recovered
        .guard_recovery(&mut restarted, &mut Ledger::default())
        .unwrap();
    assert_eq!(
        recovered.next_ordinal(
            TurnId(1),
            iteron_kernel::effect_class::EffectClass::Provider
        ),
        1
    );
    drop(restarted);
    std::fs::remove_dir_all(&host.workspace).unwrap();
}

#[tokio::test]
async fn active_ticket_cannot_reenter_and_followup_has_only_one_logical_start() {
    let mut host = Harness::new();
    let mut route = route();
    assert!(
        host.owner()
            .initial(&mut route, None, false, objective())
            .await
            .unwrap()
            .is_none()
    );
    let id = route.ticket().unwrap().effect_id().clone();
    assert!(matches!(
        host.owner()
            .initial(&mut route, None, false, objective())
            .await,
        Err(KernelError::EffectBoundary(_))
    ));
    assert_eq!(route.ticket().unwrap().effect_id(), &id);
    assert!(matches!(
        host.owner().followup(&mut route, false, objective()).await,
        Err(KernelError::EffectBoundary(_))
    ));
    assert_eq!(route.ticket().unwrap().effect_id(), &id);
    // This fixture never executes IO: close the admitted ticket using the actual known-zero
    // terminal barrier, then admit a genuine retry from the settled route state.
    host.owner()
        .close_zero(&mut route, "fixture did not dispatch")
        .unwrap();
    route.settled();
    host.owner()
        .followup(&mut route, false, objective())
        .await
        .unwrap();
    assert_eq!(route.physical_attempt(), 2);
    host.owner()
        .close_zero(&mut route, "fixture retry did not dispatch")
        .unwrap();
    let rows = host.rows();
    assert_eq!(
        rows.iter()
            .filter(|row| matches!(row.kind, EventKind::TurnStart))
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|row| matches!(row.kind, EventKind::EffectIntent { .. }))
            .count(),
        2
    );
}
