//! Trusted finite port composition for the ordinary writer. Native effect executors and mutable
//! state remain in their independent owners; this dispatcher captures current scope at each IO.
use super::coding_run_coordinator::{
    CodingRunCoordinator, CodingRunWork, ProviderRunProgress, ResponseSelection,
};
use super::coding_run_driver::CodingRunDriver;
use super::context_runtime::ContextBudgetRecoveryStage;
use super::hooks::HookDecision;
use super::model_response::ModelResponseScope;
use super::request_recovery_driver::RequestRecoveryWork;
use super::session_control::InboundControl;
use super::tool_result_projection::ToolResultProjectionPolicy;
use super::turn_completion::CompletionAction;
use super::{Agent, KernelError, Outcome};
use iteron_protocol::{EventKind, ImageContent, LifecyclePayload, Phase, TurnId};
use std::time::Instant;

impl Agent {
    pub(super) async fn drive_admitted_loop(
        &mut self,
        driver: &mut CodingRunDriver,
        task: &str,
        images: &[ImageContent],
    ) -> Result<Outcome, KernelError> {
        self.resolve_injection_before_provider(task).await?;
        self.context_estimator.invalidate_transcript();
        self.effect_journal.begin_operator_turn();
        let mut run = CodingRunCoordinator::new(driver);
        loop {
            let turn = TurnId(self.seq_turn);
            match run.work()? {
                CodingRunWork::Iteration => {
                    if self.cross_plantcore_logical_turn_gate().await.is_err() {
                        if let Some(outcome) =
                            self.collect_and_finish_requested_control(turn).await?
                        {
                            return Ok(outcome);
                        }
                        return self.finish(turn, Outcome::Interrupted).await;
                    }
                    let messages = run.begin_iteration(turn)?;
                    self.admit_pending_steers(turn, messages)?;
                    self.admit_parent_mailbox(turn, messages)?;
                    self.observe_session_memory_activation(turn, task);
                    let observed = Instant::now();
                    self.lifecycle_event(
                        "context.assembly.started",
                        Some(turn),
                        LifecyclePayload::default(),
                    );
                    if std::mem::take(&mut self.recording_harness_error_armed) {
                        return self.finish(turn, Outcome::HarnessError).await;
                    }
                    if self.record_failed {
                        return Ok(Outcome::HarnessError);
                    }
                    if let Some(outcome) = self.finish_requested_control(turn).await? {
                        return Ok(outcome);
                    }
                    let seed =
                        self.request_cycle_seed(turn, images, task, run.convergence(), observed)?;
                    run.prepare(seed, &mut self.context_estimator)?;
                }
                CodingRunWork::Recovery => {
                    let requested = run.request()?.requested_output()?;
                    let recovery_turn = run.recovery_turn()?;
                    match run.recovery_work()? {
                        RequestRecoveryWork::Gate(payload) => {
                            let report = self
                                .brokered_lifecycle_gate(
                                    recovery_turn,
                                    ContextBudgetRecoveryStage::Considered.event_id(),
                                    payload,
                                )
                                .await?;
                            run.request_mut()?
                                .gated(matches!(report.decision, HookDecision::Allow))?;
                        }
                        RequestRecoveryWork::Summary(middle) => {
                            let result = self.summarize_compaction(middle, None).await;
                            run.request_mut()?
                                .summary_completed(result, TurnId(self.seq_turn))?;
                        }
                        RequestRecoveryWork::ControlBarrier => {
                            let _ = self.collect_inbound_ops(TurnId(self.seq_turn));
                            if let Some(outcome) =
                                self.finish_requested_control(TurnId(self.seq_turn)).await?
                            {
                                return Ok(outcome);
                            }
                            run.request_mut()?.control_checked(TurnId(self.seq_turn))?;
                        }
                        RequestRecoveryWork::Coverage { middle, summary } => {
                            let result = self.verify_compaction_summary(middle, summary).await;
                            run.request_mut()?
                                .coverage_completed(result, TurnId(self.seq_turn))?;
                        }
                        RequestRecoveryWork::AssessAndCommit => {
                            let output = self.funded_provider_output_ceiling(
                                iteron_provider::output_ceiling::ProviderOutputBudget {
                                    model: &self.model,
                                    requested_max_tokens: requested,
                                    thinking_budget: self.effort_thinking_budget(self.effort),
                                },
                            )?;
                            let window = self.execution_context_window();
                            let accounting = self.request_accounting();
                            let (mut journal, scope, estimator, state) =
                                self.compaction_commit_ports();
                            if run.request_mut()?.assess_and_commit(
                                window,
                                output,
                                accounting,
                                &mut journal,
                                scope,
                                estimator,
                                state,
                            )? {
                                self.input_file_evidence = None;
                            }
                        }
                        RequestRecoveryWork::Complete => {
                            let _ = self.collect_inbound_ops(TurnId(self.seq_turn));
                            if let Some(outcome) =
                                self.finish_requested_control(TurnId(self.seq_turn)).await?
                            {
                                return Ok(outcome);
                            }
                            run.recovery_finished()?;
                        }
                    }
                }
                CodingRunWork::Request => {
                    let requested = run.request()?.requested_output()?;
                    let output = self.funded_provider_output_ceiling(
                        iteron_provider::output_ceiling::ProviderOutputBudget {
                            model: &self.model,
                            requested_max_tokens: requested,
                            thinking_budget: self.effort_thinking_budget(self.effort),
                        },
                    )?;
                    let rebound =
                        run.request_mut()?
                            .bind(turn, self.execution_context_window(), output)?;
                    if rebound.turn_changed {
                        self.observe_session_memory_activation(turn, task);
                    }
                    if self.input_image_evidence.is_none() {
                        self.remember_token_estimate_baseline(turn, rebound.baseline);
                    }
                    if let Some(reason) = self.inference_budget_exhaustion()? {
                        return self.finish(turn, Outcome::BudgetExhausted(reason)).await;
                    }
                    if run.request()?.error_streak() >= self.budget.max_consecutive_tool_errors {
                        return self.finish(turn, Outcome::Stuck).await;
                    }
                    let provider = self.provider.clone();
                    let session =
                        self.coding_request_session(turn, run.request()?.messages()?, images);
                    if let Some(control) = run.admit(session, turn, provider.as_ref()).await? {
                        debug_assert_ne!(control, InboundControl::None);
                        if let Some(outcome) = self.finish_requested_control(turn).await? {
                            return Ok(outcome);
                        }
                        return self.finish(turn, Outcome::Interrupted).await;
                    }
                }
                CodingRunWork::ProviderBegin => {
                    let admitted = run.admitted_request()?;
                    let wait = self.activity.span(
                        super::turn_activity::ActivityStage::AdmissionWait,
                        Some(turn),
                    );
                    self.ensure_policy_evidence()?;
                    let admission = self
                        .admit_provider_dispatch(turn, &admitted.request)
                        .await?;
                    wait.complete();
                    let trust = self.governing_turn_trust(run.messages());
                    let (start, usd) = self.provider_turn_start(
                        super::provider_turn_entry::ProviderTurnRequest {
                            turn,
                            request: admitted.request,
                            requested_output: admitted.requested_max_tokens,
                            argument_trust: trust,
                            early_effects: run.early_effects_allowed()
                                && self.verify_command.is_none(),
                        },
                        admission,
                    )?;
                    let now = self.pricing_now();
                    let context =
                        u64::try_from(run.evidence()?.estimate.total_tokens).unwrap_or(u64::MAX);
                    run.begin_provider(
                        self.coding_provider_session(context, trust),
                        start,
                        usd,
                        now,
                    )
                    .await?;
                }
                CodingRunWork::ProviderPump => {
                    let evidence = run.evidence()?;
                    let context = u64::try_from(evidence.estimate.total_tokens).unwrap_or(u64::MAX);
                    let trust = self.governing_turn_trust(run.messages());
                    if let ProviderRunProgress::Complete(Some(snapshot)) = run
                        .pump_provider(self.coding_provider_session(context, trust))
                        .await?
                    {
                        self.last_rate_limit = Some(snapshot);
                        self.lifecycle_event(
                            "model.quota_updated",
                            Some(turn),
                            LifecyclePayload::default(),
                        );
                    }
                }
                CodingRunWork::Hedge => {
                    let started = Instant::now();
                    let spec = run.hedge_spec()?;
                    let dispatch = self
                        .execute_hedged_provider_turn(
                            turn,
                            spec.provider,
                            spec.route,
                            spec.request,
                            spec.deadline,
                            spec.transition,
                            spec.retry_index,
                            spec.first_attempt,
                            spec.permit,
                            spec.manifests,
                        )
                        .await?;
                    run.hedge_returned(dispatch, started)?;
                }
                CodingRunWork::ResponseRecovery => {
                    let (journal, scope) = self.provider_response_ports(turn);
                    if let Some(failure) = run.recover_response(journal, scope).await? {
                        if failure.observe_physical_usage {
                            self.emit_plantcore_turn_usage(turn)?;
                        }
                        if let Some(outcome) =
                            self.collect_and_finish_requested_control(turn).await?
                        {
                            return Ok(outcome);
                        }
                        if let Some(terminal) = failure.terminal {
                            return self.finish(turn, terminal).await;
                        }
                        return Err(failure.error);
                    }
                }
                CodingRunWork::Usage => {
                    run.record_usage(self.coding_commit_session(run.evidence()?))
                        .await?;
                }
                CodingRunWork::UsageObservation => {
                    if let Err(error) = self.emit_plantcore_turn_usage(turn) {
                        run.abort_response(self.coding_commit_session(run.evidence()?))
                            .await?;
                        return Err(error);
                    }
                    run.usage_observed()?;
                }
                CodingRunWork::Reconcile => {
                    let event = run.reconcile(self.coding_commit_session(run.evidence()?))?;
                    self.ui(event);
                }
                CodingRunWork::Assistant => {
                    run.assistant(self.coding_commit_session(run.evidence()?))
                        .await?;
                }
                CodingRunWork::ResponseBoundary => {
                    if let Some(gate) = self.plantcore_dispatch_gate() {
                        gate.await_recording_provider_usage_settled()
                            .await
                            .map_err(|reason| KernelError::ContextResolution(reason.into()))?;
                        if let Some(outcome) =
                            self.collect_and_finish_requested_control(turn).await?
                        {
                            return Ok(outcome);
                        }
                    }
                    if let Some(terminal) = self.plantcore_terminal() {
                        return match terminal {
                            super::plantcore::PlantcoreTerminal::Budget(reason) => {
                                self.finish(turn, Outcome::BudgetExhausted(reason)).await
                            }
                            super::plantcore::PlantcoreTerminal::UsageUnavailable => {
                                self.finish(turn, Outcome::HarnessError).await
                            }
                        };
                    }
                    run.response_boundary()?;
                }
                CodingRunWork::ResponsePhase => {
                    let visible_bytes = self.tool_output_spill.as_ref().map_or(
                        super::tool_output_spill::DEFAULT_TOOL_OUTPUT_MEMORY_THRESHOLD_BYTES,
                        |store| store.visible_threshold_bytes(),
                    );
                    let total = run.prepare_response(ToolResultProjectionPolicy {
                        budget: &self.context_budget_policy,
                        visible_bytes,
                        inspection: run.evidence()?.inspection,
                    })?;
                    if total > 0 || self.verify_command.is_some() {
                        self.emit(
                            turn,
                            EventKind::Phase {
                                phase: Phase::Tools,
                            },
                        );
                    }
                    run.response_phase_recorded()?;
                }
                CodingRunWork::ResponseSelection => {
                    #[cfg(feature = "legacy-plantcore")]
                    if let Some(outcome) =
                        self.compose_legacy_input_response(&mut run, turn).await?
                    {
                        return Ok(outcome);
                    }
                    // A legacy refused sole-call continuation can have consumed this phase.
                    #[cfg(feature = "legacy-plantcore")]
                    if !matches!(run.work()?, CodingRunWork::ResponseSelection) {
                        continue;
                    }
                    match run.response_selection(
                        &self.registry,
                        &self.workspace,
                        self.verify_command.is_some(),
                    )? {
                        ResponseSelection::Malformed => {
                            run.abort_early(self.early_tool_collection(turn)).await?;
                            if let Some(outcome) =
                                self.collect_and_finish_requested_control(turn).await?
                            {
                                return Ok(outcome);
                            }
                            return Err(iteron_provider::ProviderError::Decode("provider emitted complete tool calls with a non-tool terminal reason".into()).into());
                        }
                        ResponseSelection::Tools(replayed) => {
                            for event in replayed {
                                self.ui(event);
                            }
                        }
                        ResponseSelection::Model => {}
                    }
                }
                CodingRunWork::ModelCompletion => {
                    run.observe_tools_elapsed(&mut self.ledger)?;
                    if let Some(outcome) = self.collect_and_finish_requested_control(turn).await? {
                        return Ok(outcome);
                    }
                    let exhausted = self.completed_turn_budget_exhaustion();
                    let interactive = self.interactive_approvals;
                    let configured_verifier = self.verify_command.is_some();
                    let scope = ModelResponseScope {
                        exhausted,
                        interactive,
                        configured_verifier,
                        task,
                        answer: &self.last_assistant_text,
                        recovered_stream: false,
                    };
                    let decision = run.model_decision(scope)?;
                    run.complete_model(decision, self.turn_completion(turn))
                        .await?;
                }
                CodingRunWork::ToolPump => {
                    let session =
                        self.tool_execution_session(turn, run.messages(), run.projection()?);
                    if let Err(error) = run.pump_tools(session).await {
                        if matches!(&error, KernelError::UnknownEffects { .. })
                            && let Some(outcome) =
                                self.collect_and_finish_requested_control(turn).await?
                        {
                            return Ok(outcome);
                        }
                        return Err(error);
                    }
                }
                CodingRunWork::Kernel => {
                    let call = run.kernel_call()?;
                    let (execution, output) = self.kernel_special_execution(
                        turn,
                        call.index,
                        call.kind,
                        run.projection()?,
                    );
                    let result = match execution
                        .run(turn, call.index, &call.call, call.capability, output)
                        .await
                    {
                        Ok(result) => result,
                        Err(error) => {
                            if matches!(&error, KernelError::UnknownEffects { .. })
                                && let Some(outcome) =
                                    self.collect_and_finish_requested_control(turn).await?
                            {
                                return Ok(outcome);
                            }
                            return Err(error);
                        }
                    };
                    run.kernel_returned(result)?;
                }
                CodingRunWork::ToolSettlement => {
                    run.observe_tools_elapsed(&mut self.ledger)?;
                    let events = self.tool_events(turn);
                    let remaining = self.remaining_inference_turns();
                    let images = if run.has_tool_images()? {
                        Some(self.tool_image_projection(turn))
                    } else {
                        None
                    };
                    if run.settle_tools(images, &events, remaining).await? {
                        self.advertised_tool_specs_cache = None;
                    }
                }
                CodingRunWork::ToolCompletion => {
                    run.complete_tools(self.turn_completion(turn)).await?;
                }
                CodingRunWork::Completion => match run.take_completion()? {
                    CompletionAction::Continue { .. } => {
                        self.advance_turn().await?;
                        run.continued()?;
                    }
                    CompletionAction::Finish {
                        outcome,
                        publish_answer,
                    } => {
                        if publish_answer {
                            self.publish_available_answer(turn, run.answer_blocks()?)?;
                        }
                        return self.finish(turn, outcome).await;
                    }
                    CompletionAction::Drain => return self.finish_drained(turn).await,
                    CompletionAction::RequestedControl => {
                        if let Some(outcome) = self.finish_requested_control(turn).await? {
                            return Ok(outcome);
                        }
                        return self.finish(turn, Outcome::Interrupted).await;
                    }
                },
            }
        }
    }
}
