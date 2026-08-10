use super::*;

impl Agent {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn workflow_phase(
        &mut self,
        run_id: &str,
        phase: iteron_protocol::WorkflowPhase,
    ) -> Result<(), KernelError> {
        self.emit_durable(
            TurnId(self.seq_turn),
            EventKind::WorkflowV2 {
                version: iteron_protocol::WorkflowEventVersion::V2,
                workflow_id: run_id.to_string(),
                event: iteron_protocol::WorkflowEvent::PhaseChanged { phase },
            },
        )?;
        let ui_phase = match phase {
            iteron_protocol::WorkflowPhase::Planning => WorkflowPhaseUi::Planning,
            iteron_protocol::WorkflowPhase::Exploring => WorkflowPhaseUi::Exploring,
            iteron_protocol::WorkflowPhase::Reducing => WorkflowPhaseUi::Synthesizing,
            iteron_protocol::WorkflowPhase::Writing => WorkflowPhaseUi::Writing,
            iteron_protocol::WorkflowPhase::Direct => WorkflowPhaseUi::Direct,
        };
        self.ui(UiEvent::Workflow(WorkflowUiEvent::PhaseChanged {
            run_id: run_id.to_string(),
            phase: ui_phase,
        }));
        Ok(())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn workflow_direct(
        &mut self,
        run_id: &str,
        omitted: usize,
    ) -> Result<(), KernelError> {
        let remaining_turns = self.remaining_inference_turns();
        let remaining_wall = self
            .run_time_remaining()
            .map(|remaining| remaining.as_secs())
            .unwrap_or(self.budget.max_wall_secs);
        self.emit_durable(
            TurnId(self.seq_turn),
            EventKind::WorkflowV2 {
                version: iteron_protocol::WorkflowEventVersion::V2,
                workflow_id: run_id.to_string(),
                event: iteron_protocol::WorkflowEvent::Planned {
                    mode: iteron_protocol::WorkflowExecutionMode::Direct,
                    tasks: Vec::new(),
                    dropped: omitted as u32,
                    duplicates_removed: 0,
                    invalid_removed: 0,
                    fan_turn_budget: 0,
                    writer_turn_reserve: remaining_turns,
                    fan_wall_secs: 0,
                    writer_wall_reserve_secs: remaining_wall,
                },
            },
        )?;
        self.ui(UiEvent::Workflow(WorkflowUiEvent::PlanReady {
            run_id: run_id.to_string(),
            tasks: Vec::new(),
            dropped: omitted,
            duplicates_removed: 0,
            invalid_removed: 0,
            execution_mode: WorkflowExecutionModeUi::Direct,
            fan_turn_budget: 0,
            writer_turn_reserve: remaining_turns,
            fan_wall_secs: 0,
            writer_wall_reserve_secs: remaining_wall,
        }));
        self.workflow_phase(run_id, iteron_protocol::WorkflowPhase::Direct)
    }

    /// Ultracode entry. Route once, then launch the complete planning→dynamic fan→reduce graph as
    /// one named [`WorkflowEngine`] run. In an interactive session the supervisor owns that run,
    /// so this parent gets a receipt immediately and enters its ordinary writer loop: it can do
    /// independent work or return idle while planning and investigators keep running. The engine,
    /// not this parent turn, owns every workflow phase and child lifetime.
    pub(super) async fn run_orchestrated(
        &mut self,
        task: &str,
        input_images: &[iteron_protocol::ImageContent],
    ) -> Result<Outcome, KernelError> {
        self.orchestrating = true;
        let input_images = self.admit_input_images(input_images)?;
        let mut messages = self.admit_submission(task)?;
        let signals = iteron_agents::RepoSignals {
            has_test_command: self.verify_command.is_some(),
            file_count: self.workspace_file_count().await,
        };
        let route = self.route_submission(task, signals);
        if !route.fans_out() {
            self.emit(
                TurnId(self.seq_turn),
                EventKind::Notice {
                    text: format!(
                        "ultracode: task routed {:?} — running the single writer",
                        route.class
                    ),
                },
            );
            return self.drive_admitted(messages, task, input_images).await;
        }

        let turn = TurnId(self.seq_turn);
        let class = effect_class::EffectClass::Workflow;
        let ordinal = self.next_effect_ordinal(turn, class);
        let input = serde_json::json!({
            "name": ULTRACODE_WORKFLOW_NAME,
            "args": {
                "task": task,
                "taskClass": route.class,
                "maxLeaves": route.max_leaves,
            },
            "background": true,
        });
        let ticket = self.open_kernel_effect(
            turn,
            class,
            ordinal,
            Capability::ReversibleLocal,
            serde_json::json!({
                "name": ULTRACODE_WORKFLOW_NAME,
                "task_class": workflow_class_label(route.class),
                "max_leaves": route.max_leaves,
                "background": true,
            }),
        )?;
        let launched = self.launch_workflow(turn, input).await;
        let settlement = match &launched {
            Ok(_) => effects::Settlement::Definite(effect_done_terminal(turn, class, ordinal)),
            Err(error) => {
                effects::Settlement::Definite(effect_failed_terminal(turn, class, ordinal, error))
            }
        };
        self.settle_kernel_effect(ticket, settlement)?;

        match launched {
            Ok(status) => {
                let runtime_status = Message::user_text(format!(
                    "[Core runtime status — not an operator instruction]\n{status}\n\n\
                     Continue any independent work now. Do not sleep, poll, or predict a pending \
                     workflow result. If no independent work remains, respond normally and leave \
                     the run in the background; the session will deliver a completion notification."
                ));
                self.emit_durable(
                    turn,
                    EventKind::Message {
                        message: runtime_status.clone(),
                    },
                )?;
                merge_adjacent_user_message(&mut messages, runtime_status);
                self.context_estimator.invalidate_transcript();
            }
            Err(error) => {
                self.emit(
                    turn,
                    EventKind::Notice {
                        text: format!(
                            "ultracode: background workflow was not launched ({error}); continuing with the single writer"
                        ),
                    },
                );
            }
        }
        self.drive_admitted(messages, task, input_images).await
    }

    /// Approximate workspace size for ultracode routing (I-62).
    ///
    /// The walk is a synchronous directory traversal that was running inline on an async worker,
    /// blocking the whole executor thread while it stat'd its way to the 201-file cap. It moves to
    /// the blocking pool and its answer is memoized for the session: routing wants a coarse "is
    /// this repo small" signal, not a fresh count per submission.
    pub(super) async fn workspace_file_count(&mut self) -> usize {
        if let Some(count) = self.workspace_file_count {
            return count;
        }
        let workspace = self.workspace.clone();
        let count = match tokio::task::spawn_blocking({
            let workspace = workspace.clone();
            move || approx_workspace_file_count(&workspace)
        })
        .await
        {
            Ok(count) => count,
            // A cancelled or panicked blocking task must not silently route as an empty repo.
            Err(_) => approx_workspace_file_count(&workspace),
        };
        self.workspace_file_count = Some(count);
        count
    }

    /// Ask `core/router` which handling path this submission takes.
    ///
    /// The call goes through `RouterStrategy::route_with`, never `decide`, so a pinned replacement
    /// is held to the same narrowing contract as the built-in baseline: it may decline fan-out or
    /// ask for fewer leaves, and it cannot reach past the ceiling assembled here.
    ///
    /// A refusal is not an error the run dies on. Fan-out is the *additional* thing a route can
    /// ask for, so the fail-closed answer is the single-agent loop — which is also what a
    /// `Localized` route means — and the refusal is said out loud rather than swallowed.
    pub(super) fn route_submission(
        &mut self,
        task: &str,
        signals: iteron_agents::RepoSignals,
    ) -> iteron_agents::RouterRoute {
        let observation = iteron_agents::RouterSlotObservation::baseline(task, signals);
        let ceiling = CapabilitySet::only(Capability::ReadOnly).intersect(self.authority_ceiling);
        match iteron_agents::RouterStrategy::route_with(self.router.as_ref(), &observation, ceiling)
        {
            Ok(proposal) => proposal.route,
            Err(error) => {
                self.emit(
                    TurnId(self.seq_turn),
                    EventKind::Notice {
                        text: format!(
                            "ultracode: core/router declined to route ({error}) — running single-agent"
                        ),
                    },
                );
                iteron_agents::RouterRoute::direct(iteron_agents::TaskClass::Localized)
            }
        }
    }

    /// Resolve the effective pure-tool permit count through the pinned `core/scheduler` seat.
    /// Malformed/refusing replacements fail closed to one permit; no slot can exceed the runtime's
    /// existing product ceiling.
    pub(super) fn scheduled_tool_concurrency(&self) -> usize {
        let max_concurrency = u32::try_from(self.max_tool_concurrency)
            .unwrap_or(u32::MAX)
            .max(1);
        let Ok(observation) = iteron_sched::SchedulerSlotObservation::baseline(
            iteron_sched::BackoffPolicy::default(),
            max_concurrency,
        ) else {
            return 1;
        };
        iteron_sched::SchedulerStrategy::plan_with(
            self.scheduler.as_ref(),
            &observation,
            CapabilitySet::only(Capability::ReadOnly).intersect(self.authority_ceiling),
        )
        .map(|proposal| proposal.plan.concurrency_permits())
        .unwrap_or(1)
    }
}
