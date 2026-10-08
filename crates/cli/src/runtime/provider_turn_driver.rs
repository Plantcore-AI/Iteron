//! One executable model round: route/physical ticket, stream tasks, refusal and followup phase
//! live here. Concrete journals are borrowed only across their actual barriers. Memory exposure
//! remains an explicit host safe point between native prepared inclusion and physical terminal.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::effect_journal_owner::EffectJournalOwner;
use super::memory_request_exposure::MemoryRequestExposure;
use super::policy_evidence_recorder::PolicyEvidenceRecorder;
use super::provider_attempt_journal::{ProviderAttemptJournal, ProviderLogicalUsageEvidence};
use super::provider_dispatch::{
    ProviderAdmissionJournal, ProviderDispatchOwner, ProviderDispatchScope,
    ProviderObjectiveEvidence,
};
use super::provider_execution_scope::{
    ProviderExecutionConfiguration, ProviderExecutionEvidence, ProviderExecutionJournal,
    ProviderExecutionScope,
};
use super::provider_extension::{ProviderExtensionPort, ProviderExtensionTerminal};
use super::provider_financial_source::ProviderFinancialSource;
use super::provider_followup::{
    ProviderFollowupDecision, ProviderFollowupOwner, ProviderFollowupScope,
};
use super::provider_governor_state::GovernedProviderRoute;
use super::provider_hedge::HedgedProviderDispatch;
use super::provider_round::ProviderRoundOwner;
use super::provider_route_admission::ProviderRouteAdmission;
use super::provider_route_binding::{
    ProviderRouteBindingJournal, ProviderRouteBindingOwner, ProviderRouteBindingScope,
};
use super::provider_route_events::ProviderRouteEvents;
use super::provider_route_journal::ProviderRouteJournal;
use super::provider_route_turn::ProviderRouteTurn;
use super::provider_selection::ProviderSelectionOwner;
use super::provider_selection_journal::ProviderSelectionJournal;
use super::provider_stream_observer::ProviderStreamScope;
use super::request_manifest::RequestManifestFactory;
use super::session_control::SessionControlState;
use super::stream_tool_events::StreamToolEvents;
use super::terminal_record::TerminalRecordOwner;
use super::turn_activity::ActivityStage;
use super::turn_publication::TurnPublicationOwner;
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::Ledger;
use iteron_protocol::LifecyclePayload;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::StrategySlot;
use iteron_provider::{
    AttemptPermit, Provider, ProviderGovernor, ProviderRequestControls, TurnRequest, TurnResult,
};
use iteron_record::Rollout;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub(super) struct ProviderTurnJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    pub(super) policy: Option<&'a mut PolicyEvidenceRecorder>,
    pub(super) terminal: &'a mut TerminalRecordOwner,
    pub(super) publications: &'a mut TurnPublicationOwner,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}

/// These are the actual resident route slots. Their authoritative selection/card stays in the
/// selection owner, with provider/model swaps made only by the durable binding transaction.
pub(super) struct ProviderTurnResident<'a> {
    pub(super) selection: &'a mut ProviderSelectionOwner,
    pub(super) provider: &'a mut Arc<dyn Provider>,
    pub(super) model: &'a mut String,
    pub(super) context_window: &'a mut Option<u64>,
    pub(super) max_output: &'a mut Option<u32>,
}

/// Fixed admission policy, plus live control/governor ports. No mutable session proxy is present.
#[derive(Clone)]
pub(super) struct ProviderTurnEnvironment<'a> {
    pub(super) workspace: &'a Path,
    pub(super) routes: &'a [GovernedProviderRoute],
    pub(super) governor: Option<&'a ProviderGovernor>,
    pub(super) control: &'a SessionControlState,
    pub(super) router: &'a dyn StrategySlot,
    pub(super) authority: CapabilitySet,
    pub(super) controls: ProviderRequestControls,
    pub(super) strict_controls: bool,
    pub(super) require_fallback_pricing: bool,
    pub(super) output_proof_required: bool,
    pub(super) context_tokens: u64,
    pub(super) run_deadline: Option<Instant>,
    #[cfg(test)]
    pub(super) pricing_now_unix_secs: Option<u64>,
}

pub(super) struct ProviderTurnStart {
    pub(super) route: ProviderRouteTurn,
    pub(super) route_permit: Option<AttemptPermit>,
    pub(super) refusal: Option<KernelError>,
    pub(super) hedged: bool,
    pub(super) execution: ProviderExecutionConfiguration,
    pub(super) events: ProviderRouteEvents,
    pub(super) manifests: RequestManifestFactory,
    pub(super) financial: ProviderFinancialSource,
    pub(super) prefix_limit: usize,
}

pub(super) struct ProviderHedgeSpec<'a> {
    pub(super) provider: Arc<dyn Provider>,
    pub(super) route: &'a str,
    pub(super) request: &'a TurnRequest,
    pub(super) deadline: Instant,
    pub(super) transition: Option<&'static str>,
    pub(super) retry_index: u32,
    pub(super) first_attempt: bool,
    pub(super) permit: Option<AttemptPermit>,
    pub(super) manifests: &'a RequestManifestFactory,
}

pub(super) struct CompletedProviderTurn {
    pub(super) route: ProviderRouteTurn,
    pub(super) round: ProviderRoundOwner,
    pub(super) execution: ProviderExecutionScope,
    pub(super) result: Result<TurnResult, KernelError>,
    pub(super) usage_evidence: ProviderLogicalUsageEvidence,
}

pub(super) enum ProviderPumpProgress {
    AwaitHedge,
    Completed(Result<TurnResult, KernelError>),
}

pub(super) struct ProviderTurnDriver {
    route: ProviderRouteTurn,
    round: ProviderRoundOwner,
    execution: ProviderExecutionScope,
    events: ProviderRouteEvents,
    manifests: RequestManifestFactory,
    financial: ProviderFinancialSource,
    refusal: Option<KernelError>,
    hedged: bool,
    usage_evidence: ProviderLogicalUsageEvidence,
}

impl ProviderTurnDriver {
    /// Own the actual physical execution/settlement/followup loop. Only the optional independent
    /// hedge executor returns to composition; ordinary retry/fallback never exits this owner.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn pump(
        &mut self,
        mut journal: ProviderTurnJournal<'_>,
        environment: ProviderTurnEnvironment<'_>,
        mut resident: ProviderTurnResident<'_>,
        mut extension: ProviderExtensionPort<'_>,
        evidence: ProviderExecutionEvidence<'_>,
        mut memory: MemoryRequestExposure<'_>,
        mut hedge: Option<(HedgedProviderDispatch, Instant)>,
    ) -> Result<ProviderPumpProgress, KernelError> {
        loop {
            if self.hedged && self.refusal.is_none() && hedge.is_none() {
                return Ok(ProviderPumpProgress::AwaitHedge);
            }
            let (hedged, started) = hedge
                .take()
                .map(|(dispatch, started)| (Some(dispatch), started))
                .unwrap_or_else(|| (None, Instant::now()));
            let mut evidence = evidence.clone();
            evidence.requested_control =
                environment.control.requested() != super::session_control::InboundControl::None;
            self.execute(journal.reborrow(), evidence, hedged, started)
                .await?;
            // The genuine native prepared archive proof is folded before physical terminal;
            // no semantic TurnRequest, route selection or fabricated result grants Used.
            memory.prepared(&self.manifests);
            if let Some(result) = self
                .advance(
                    journal.reborrow(),
                    environment.clone(),
                    resident.reborrow(),
                    extension.reborrow(),
                    environment.current_pricing_now(),
                )
                .await?
            {
                if !self.inclusion_confirmed() {
                    memory.unconfirmed();
                }
                return Ok(ProviderPumpProgress::Completed(result));
            }
        }
    }

    pub(super) async fn begin(
        mut start: ProviderTurnStart,
        mut journal: ProviderTurnJournal<'_>,
        environment: ProviderTurnEnvironment<'_>,
        resident: &ProviderTurnResident<'_>,
        extension: ProviderExtensionPort<'_>,
        pricing_now: u64,
        loop_state: &mut super::agent_loop::AgentLoopGuard,
    ) -> Result<Self, KernelError> {
        start.route.assign_route_permit(start.route_permit.take());
        let financial = start.financial.selected(
            resident.selection,
            start.route.provider().as_ref(),
            &start.route.request().model,
        );
        let objective = objective(environment.routes, start.route.route_id());
        let refusal = journal
            .dispatch(
                financial,
                pricing_now,
                &environment,
                &start.events,
                extension.as_read(),
            )
            .initial(&mut start.route, start.refusal, start.hedged, objective)
            .await?;
        let mut stream_start = Instant::now();
        let (running, connect) = if refusal.is_none() {
            loop_state.transition(iteron_protocol::AgentLoopState::StreamingModel)?;
            stream_start = Instant::now();
            let running = Some(
                start
                    .events
                    .activity
                    .span(ActivityStage::RunningProvider, Some(start.events.turn)),
            );
            let connect = Some(
                start
                    .events
                    .activity
                    .span(ActivityStage::Connect, Some(start.events.turn)),
            );
            start.events.emit(
                "context.request.submitted",
                LifecyclePayload {
                    magnitude: Some(environment.context_tokens),
                    ..LifecyclePayload::default()
                },
            );
            start
                .events
                .emit("model.request_sent", LifecyclePayload::default());
            (running, connect)
        } else {
            (None, None)
        };
        let StreamToolEvents {
            frontend,
            resident_ui,
            ui,
            ..
        } = &start.execution.events;
        let round = ProviderRoundOwner::new(ProviderStreamScope {
            turn: start.events.turn,
            started: stream_start,
            prefix_limit: start.prefix_limit,
            activity: start.events.activity.clone(),
            running,
            connect,
            frontend: frontend.clone(),
            resident_ui: resident_ui.clone(),
            ui: ui.clone(),
            lifecycle: start.events.lifecycle.clone(),
            lifecycle_hooks: start.events.hooks.clone(),
            correlation: start.events.correlation.clone(),
        });
        Ok(Self {
            route: start.route,
            round,
            execution: ProviderExecutionScope::new(start.execution),
            events: start.events,
            manifests: start.manifests,
            financial: start.financial,
            refusal,
            hedged: start.hedged,
            usage_evidence: ProviderLogicalUsageEvidence::Unproven,
        })
    }

    pub(super) fn refused(&self) -> bool {
        self.refusal.is_some()
    }
    pub(super) fn hooks_gate_reads(&self) -> bool {
        self.execution.hooks_gate_reads()
    }
    pub(super) fn inclusion_confirmed(&self) -> bool {
        self.manifests.context_inclusion_confirmed()
    }

    /// The existing bounded hedge executor remains a separate physical domain. It receives the
    /// exact owned request and transfers the primary permit once; it cannot change this route.
    pub(super) fn hedge_spec(&mut self) -> Option<ProviderHedgeSpec<'_>> {
        if self.refusal.is_some() || !self.hedged {
            return None;
        }
        let permit = self.route.take_route_permit();
        Some(ProviderHedgeSpec {
            provider: self.route.provider(),
            route: self.route.route_id(),
            request: self.route.request(),
            deadline: self.execution.provider_deadline(),
            transition: self.route.transition(),
            retry_index: self.route.retry_index(),
            first_attempt: self.route.first_attempt(),
            permit,
            manifests: &self.manifests,
        })
    }

    pub(super) async fn execute(
        &mut self,
        mut journal: ProviderTurnJournal<'_>,
        evidence: ProviderExecutionEvidence<'_>,
        hedged: Option<HedgedProviderDispatch>,
        started: Instant,
    ) -> Result<(), KernelError> {
        let observer = self.route.ticket().map(|ticket| {
            self.manifests
                .for_ticket(ticket, self.route.request().max_tokens)
        });
        self.execution
            .run_attempt(
                &mut self.round,
                &mut self.route,
                journal.execution(),
                evidence,
                started,
                observer,
                hedged,
                self.refusal.take(),
            )
            .await
    }

    /// Called only after the host observes actual prepared inclusion. This owns the full
    /// terminal→followup wait→selection/price barrier→new admission→reconnect composition.
    pub(super) async fn advance(
        &mut self,
        mut journal: ProviderTurnJournal<'_>,
        environment: ProviderTurnEnvironment<'_>,
        resident: ProviderTurnResident<'_>,
        mut extension: ProviderExtensionPort<'_>,
        pricing_now: u64,
    ) -> Result<Option<Result<TurnResult, KernelError>>, KernelError> {
        let financial = self.financial.selected(
            resident.selection,
            self.route.provider().as_ref(),
            &self.route.request().model,
        );
        let completed = self.execution.settle_attempt(
            &mut self.round,
            &mut self.route,
            journal.execution(),
            financial,
            pricing_now,
            &self.events,
            extension.reborrow(),
            environment.governor.cloned(),
            environment.control,
        )?;
        self.usage_evidence = completed.usage_evidence;
        if let Some(error) = self.round.take_record_error() {
            return Ok(Some(Err(error)));
        }
        let followup = ProviderFollowupOwner {
            scope: ProviderFollowupScope {
                routes: environment.routes,
                governor: environment.governor,
                controls: environment.control,
                ledger: &mut *journal.ledger,
                events: &self.events,
                run_deadline: environment.run_deadline,
                usd: self.financial.usd.clone(),
                extension_terminal: extension.terminal(),
                output_proof_required: environment.output_proof_required,
                context_tokens: environment.context_tokens,
                financial: &self.financial,
                selected: resident.selection,
                #[cfg(test)]
                pricing_now_unix_secs: environment.pricing_now_unix_secs,
            },
        }
        .advance(
            &mut self.round,
            &mut self.route,
            completed.result,
            completed.monetary_followup_safe,
        )
        .await?;
        // Retry waits can cross a signed rate-card expiry. Fresh selection/admission must use
        // the current clock, not the timestamp captured before the physical terminal/wait.
        let pricing_now = environment.current_pricing_now();
        match followup {
            ProviderFollowupDecision::Terminal(result) => return Ok(Some(result)),
            ProviderFollowupDecision::ReAdmit => {}
            ProviderFollowupDecision::Fallback(prepared) => {
                let failover = self.events.failover();
                let candidate =
                    environment
                        .routes
                        .get(prepared.index)
                        .ok_or(KernelError::InvalidRoute(
                            "fallback route index is outside the admitted chain",
                        ))?;
                let mut binding = ProviderRouteBindingOwner {
                    selected: &mut *resident.selection,
                    provider: &mut *resident.provider,
                    model: &mut *resident.model,
                    journal: journal.binding(),
                    scope: ProviderRouteBindingScope {
                        turn: self.events.turn,
                        router: environment.router,
                        authority: environment.authority,
                        controls: environment.controls,
                        strict_controls: environment.strict_controls,
                        governor: environment.governor,
                    },
                };
                let next = binding.activate_fallback(
                    candidate,
                    prepared.class,
                    environment.require_fallback_pricing,
                    pricing_now,
                    resident.context_window,
                    resident.max_output,
                )?;
                let controls = binding.controls_for(next.provider.as_ref());
                self.route.selected_fallback(
                    next,
                    prepared.physical,
                    prepared.index,
                    prepared.class,
                    controls,
                );
                failover.complete();
                if let Err(error) =
                    followup_budget(extension.terminal(), self.financial.usd.as_ref())
                {
                    return Ok(Some(Err(error)));
                }
            }
        }
        if !self.hedged {
            let permit = ProviderRouteAdmission {
                governor: environment.governor.cloned(),
                control: environment.control,
                run_deadline: environment.run_deadline,
                events: self.events.clone(),
                journal: journal.route(),
            }
            .admit(self.route.route_id())
            .await?;
            self.route.assign_route_permit(permit);
            let financial = self.financial.selected(
                resident.selection,
                self.route.provider().as_ref(),
                &self.route.request().model,
            );
            let objective = objective(environment.routes, self.route.route_id());
            if let Err(error) = journal
                .dispatch(
                    financial,
                    pricing_now,
                    &environment,
                    &self.events,
                    extension.as_read(),
                )
                .followup(&mut self.route, false, objective)
                .await
            {
                return Ok(Some(Err(error)));
            }
        }
        self.round.restart_connect()?;
        self.events.request_sent(self.route.retry_index());
        Ok(None)
    }

    pub(super) fn finish(
        mut self,
        result: Result<TurnResult, KernelError>,
    ) -> Result<CompletedProviderTurn, KernelError> {
        self.round.close(&result, &self.events)?;
        Ok(CompletedProviderTurn {
            route: self.route,
            round: self.round,
            execution: self.execution,
            result,
            usage_evidence: self.usage_evidence,
        })
    }
}

impl ProviderTurnEnvironment<'_> {
    fn current_pricing_now(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = self.pricing_now_unix_secs {
            return now;
        }
        super::provider_accounting::unix_now_secs()
    }
}

impl ProviderTurnResident<'_> {
    fn reborrow(&mut self) -> ProviderTurnResident<'_> {
        ProviderTurnResident {
            selection: &mut *self.selection,
            provider: &mut *self.provider,
            model: &mut *self.model,
            context_window: &mut *self.context_window,
            max_output: &mut *self.max_output,
        }
    }
}

fn followup_budget(
    terminal: Option<ProviderExtensionTerminal>,
    usd: Option<&Arc<super::pricing::SharedUsdBudget>>,
) -> Result<(), KernelError> {
    if let Some(terminal) = terminal {
        return Err(KernelError::InferenceBudgetExhausted(match terminal {
            ProviderExtensionTerminal::Budget(reason) => reason,
            ProviderExtensionTerminal::UsageUnavailable => "usage_unavailable",
        }));
    }
    if usd.is_some_and(|usd| usd.exhausted()) {
        return Err(KernelError::InferenceBudgetExhausted("max_usd"));
    }
    Ok(())
}
fn objective(routes: &[GovernedProviderRoute], id: &str) -> ProviderObjectiveEvidence {
    routes.iter().find(|route| route.id() == id).map_or(
        ProviderObjectiveEvidence {
            score: None,
            digest: None,
        },
        |route| route.objective_evidence(),
    )
}

impl ProviderTurnJournal<'_> {
    fn reborrow(&mut self) -> ProviderTurnJournal<'_> {
        ProviderTurnJournal {
            rollout: &mut *self.rollout,
            effects: &mut *self.effects,
            ledger: &mut *self.ledger,
            record_failed: &mut *self.record_failed,
            diagnostics: self.diagnostics,
            policy: self.policy.as_deref_mut(),
            terminal: &mut *self.terminal,
            publications: &mut *self.publications,
            #[cfg(test)]
            fault: &mut *self.fault,
        }
    }
    fn execution(&mut self) -> ProviderExecutionJournal<'_> {
        ProviderExecutionJournal {
            rollout: &mut *self.rollout,
            effects: &mut *self.effects,
            policy: self.policy.as_deref_mut(),
            ledger: &mut *self.ledger,
            record_failed: &mut *self.record_failed,
            diagnostics: self.diagnostics,
            #[cfg(test)]
            fault: &mut *self.fault,
        }
    }
    fn binding(&mut self) -> ProviderRouteBindingJournal<'_> {
        ProviderRouteBindingJournal {
            selection: ProviderSelectionJournal {
                rollout: &mut *self.rollout,
                ledger: &mut *self.ledger,
                record_failed: &mut *self.record_failed,
                diagnostics: self.diagnostics,
                #[cfg(test)]
                fault: &mut *self.fault,
            },
            policy: self.policy.as_deref_mut(),
        }
    }
    fn route(&mut self) -> ProviderRouteJournal<'_> {
        ProviderRouteJournal {
            rollout: &mut *self.rollout,
            ledger: &mut *self.ledger,
            record_failed: &mut *self.record_failed,
            diagnostics: self.diagnostics,
            #[cfg(test)]
            fault: &mut *self.fault,
        }
    }
    fn dispatch<'a>(
        &'a mut self,
        financial: super::provider_financial_context::ProviderFinancialContext,
        pricing_now: u64,
        environment: &'a ProviderTurnEnvironment<'_>,
        events: &'a ProviderRouteEvents,
        extension: Option<&'a dyn super::provider_extension::ProviderDispatchExtension>,
    ) -> ProviderDispatchOwner<'a> {
        ProviderDispatchOwner {
            journal: ProviderAdmissionJournal {
                physical: ProviderAttemptJournal {
                    rollout: &mut *self.rollout,
                    effects: &mut *self.effects,
                    ledger: &mut *self.ledger,
                    record_failed: &mut *self.record_failed,
                    diagnostics: self.diagnostics,
                    financial,
                    pricing_now,
                    #[cfg(test)]
                    fault: &mut *self.fault,
                },
                terminal: &mut *self.terminal,
                policy: self.policy.as_deref_mut(),
                publications: &mut *self.publications,
            },
            scope: ProviderDispatchScope {
                workspace: environment.workspace,
                extension,
                events,
                control: environment.control,
                deadline: environment.run_deadline,
                #[cfg(test)]
                pricing_now_unix_secs: environment.pricing_now_unix_secs,
            },
        }
    }
}

#[cfg(all(test, unix))]
#[path = "provider_turn_driver_tests.rs"]
mod tests;
