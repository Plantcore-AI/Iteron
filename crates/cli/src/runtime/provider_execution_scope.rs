//! Per-round execution resources and the concrete stream/terminal boundary. The registry and
//! current permission evidence are borrowed only during a pump; no session proxy is retained.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::artifact_publication::ToolOutputPublicationFactory;
use super::effect_journal_owner::EffectJournalOwner;
use super::failed_action_cache::FailedActionCache;
use super::hooks::{HookEvent, Hooks, journal::HookEffectJournal};
use super::permission_policy::OperationPolicy;
use super::plantcore::PlantcoreRuntime;
use super::policy_evidence_recorder::PolicyEvidenceRecorder;
use super::provider_attempt_journal::ProviderAttemptJournal;
use super::provider_attempt_pump::{ProviderAttemptCompletion, ProviderAttemptTransport};
use super::provider_financial_context::ProviderFinancialContext;
use super::provider_hedge::HedgedProviderDispatch;
use super::provider_round::ProviderRoundOwner;
use super::provider_route_admission::ProviderRouteAdmission;
use super::provider_route_events::ProviderRouteEvents;
use super::provider_route_journal::ProviderRouteJournal;
use super::provider_route_turn::ProviderRouteTurn;
use super::provider_transport_attempt::ProviderCancellation;
use super::session_control::SessionControlState;
use super::stream_tool_admission::{StreamToolControl, StreamToolScope};
use super::stream_tool_events::StreamToolEvents;
use super::stream_tool_journal::StreamToolJournal;
use super::submitted_turn_state::SubmittedTurnState;
use super::tool_output_spill::ToolOutputSpillStore;
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::Ledger;
use iteron_protocol::slot::StrategySlot;
use iteron_protocol::{Trust, TurnId};
use iteron_provider::ProviderGovernor;
use iteron_provider::request_capture::ProviderRequestObserver;
use iteron_record::Rollout;
use iteron_sched::Governor;
use iteron_tools::Registry;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Instant;
use tokio::sync::RwLock;

pub(super) struct ProviderExecutionConfiguration {
    pub(super) turn: TurnId,
    pub(super) strategy: Arc<dyn StrategySlot>,
    pub(super) trust: Trust,
    pub(super) overlap: bool,
    pub(super) early_effects: bool,
    pub(super) hooks: Hooks,
    pub(super) hook_journal: Option<HookEffectJournal>,
    pub(super) concurrency: usize,
    pub(super) run_deadline: Option<Instant>,
    pub(super) provider_deadline: Instant,
    pub(super) interrupt: Option<Arc<AtomicBool>>,
    pub(super) force_cancel: Arc<AtomicBool>,
    pub(super) drain: Arc<AtomicBool>,
    pub(super) allow_in_flight_past_deadline: bool,
    pub(super) events: StreamToolEvents,
}

pub(super) struct ProviderExecutionEvidence<'a> {
    pub(super) workspace: &'a Path,
    pub(super) registry: &'a Registry,
    pub(super) operation: OperationPolicy<'a>,
    pub(super) failed_actions: &'a FailedActionCache,
    pub(super) recovered: &'a SubmittedTurnState,
    pub(super) requested_control: bool,
    pub(super) publication: Arc<dyn ToolOutputPublicationFactory>,
    pub(super) spill: Option<Arc<ToolOutputSpillStore>>,
}

/// One concrete WAL/ledger borrow is reborrowed in stream, physical-terminal and quota order.
pub(super) struct ProviderExecutionJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) policy: Option<&'a mut PolicyEvidenceRecorder>,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}

pub(super) struct ProviderExecutionScope {
    configuration: ProviderExecutionConfiguration,
    compatibility_hook: bool,
    lifecycle_hook: bool,
    governor: Governor,
    queued: Arc<AtomicUsize>,
    execution_gate: Arc<RwLock<()>>,
}

impl ProviderExecutionScope {
    pub(super) fn new(configuration: ProviderExecutionConfiguration) -> Self {
        let compatibility_hook = !configuration
            .hooks
            .commands(HookEvent::PreToolUse)
            .is_empty();
        let lifecycle_hook = !configuration
            .hooks
            .is_empty_for_lifecycle("tool.call_proposed");
        let governor = Governor::new(configuration.concurrency);
        Self {
            configuration,
            compatibility_hook,
            lifecycle_hook,
            governor,
            queued: Arc::new(AtomicUsize::new(0)),
            execution_gate: Arc::new(RwLock::new(())),
        }
    }

    pub(super) fn hooks_gate_reads(&self) -> bool {
        self.compatibility_hook || self.lifecycle_hook
    }

    pub(super) fn provider_deadline(&self) -> Instant {
        self.configuration.provider_deadline
    }

    pub(super) fn queued_reads(&self) -> Arc<AtomicUsize> {
        self.queued.clone()
    }

    /// The short-lived evidence borrow ends before route activation or pricing may change.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_attempt(
        &self,
        round: &mut ProviderRoundOwner,
        route: &mut ProviderRouteTurn,
        journal: ProviderExecutionJournal<'_>,
        evidence: ProviderExecutionEvidence<'_>,
        started: Instant,
        observer: Option<Arc<dyn ProviderRequestObserver>>,
        hedged: Option<HedgedProviderDispatch>,
        refusal: Option<KernelError>,
    ) -> Result<(), KernelError> {
        let configuration = &self.configuration;
        round
            .run_attempt(
                route,
                StreamToolJournal {
                    rollout: journal.rollout,
                    effects: journal.effects,
                    policy: journal.policy,
                    ledger: journal.ledger,
                    record_failed: journal.record_failed,
                    diagnostics: journal.diagnostics,
                    #[cfg(test)]
                    fault: journal.fault,
                },
                StreamToolScope {
                    turn: configuration.turn,
                    workspace: evidence.workspace,
                    registry: evidence.registry,
                    strategy: configuration.strategy.as_ref(),
                    operation: evidence.operation,
                    trust: configuration.trust,
                    failed_actions: evidence.failed_actions,
                    recovered: evidence.recovered,
                    overlap: configuration.overlap,
                    early_effects: configuration.early_effects,
                    compatibility_hook: self.compatibility_hook,
                    lifecycle_hook: self.lifecycle_hook,
                    hooks: configuration.hooks.clone(),
                    hook_journal: configuration.hook_journal.clone(),
                    governor: self.governor.clone(),
                    queued: self.queued.clone(),
                    execution_gate: self.execution_gate.clone(),
                    control: StreamToolControl {
                        deadline: configuration.run_deadline,
                        requested: evidence.requested_control,
                        interrupt: configuration.interrupt.clone(),
                        force_cancel: configuration.force_cancel.clone(),
                        drain: configuration.drain.clone(),
                    },
                    publication: evidence.publication,
                    spill: evidence.spill,
                    events: configuration.events.clone(),
                },
                ProviderAttemptTransport {
                    observer,
                    deadline: configuration.provider_deadline,
                    started,
                    cancellation: ProviderCancellation {
                        interrupt: configuration.interrupt.clone(),
                        force_cancel: configuration.force_cancel.clone(),
                        drain: configuration.drain.clone(),
                        attempt: None,
                        allow_in_flight_past_deadline: configuration.allow_in_flight_past_deadline,
                    },
                },
                hedged,
                refusal,
            )
            .await
    }

    /// A provider result is first sealed into the physical WAL/controller. Governor observations
    /// follow that receipt, and permits are released only after those observations succeed.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn settle_attempt(
        &self,
        round: &mut ProviderRoundOwner,
        route: &mut ProviderRouteTurn,
        journal: ProviderExecutionJournal<'_>,
        financial: ProviderFinancialContext,
        pricing_now: u64,
        events: &ProviderRouteEvents,
        plantcore: &mut PlantcoreRuntime,
        projected_at: u64,
        governor: Option<ProviderGovernor>,
        control: &SessionControlState,
    ) -> Result<ProviderAttemptCompletion, KernelError> {
        let completed = round.settle_attempt(
            route,
            ProviderAttemptJournal {
                rollout: &mut *journal.rollout,
                effects: journal.effects,
                ledger: &mut *journal.ledger,
                record_failed: &mut *journal.record_failed,
                diagnostics: journal.diagnostics,
                financial,
                pricing_now,
                #[cfg(test)]
                fault: &mut *journal.fault,
            },
            events,
            plantcore,
            projected_at,
        )?;
        if completed.single_dispatched && !completed.hedged {
            ProviderRouteAdmission {
                governor,
                control,
                run_deadline: self.configuration.run_deadline,
                events: ProviderRouteEvents {
                    turn: events.turn,
                    lifecycle: events.lifecycle.clone(),
                    hooks: events.hooks.clone(),
                    correlation: events.correlation.clone(),
                    activity: events.activity.clone(),
                },
                journal: ProviderRouteJournal {
                    rollout: journal.rollout,
                    ledger: journal.ledger,
                    record_failed: journal.record_failed,
                    diagnostics: journal.diagnostics,
                    #[cfg(test)]
                    fault: journal.fault,
                },
            }
            .observe(route.route_id(), &completed.result, completed.quota)?;
        }
        round.release_attempt(route)?;
        Ok(completed)
    }
}
