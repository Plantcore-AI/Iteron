use super::*;

impl App {
    /// Project one id-correlated kernel lifecycle update into one live workflow card.
    pub(super) fn workflow_event(&mut self, event: WorkflowUiEvent) {
        let existing_block_id = match &event {
            WorkflowUiEvent::RunStarted { run_id, .. }
            | WorkflowUiEvent::PlanReady { run_id, .. }
            | WorkflowUiEvent::PhaseChanged { run_id, .. }
            | WorkflowUiEvent::AgentStarted { run_id, .. }
            | WorkflowUiEvent::AgentActivity { run_id, .. }
            | WorkflowUiEvent::AgentFinished { run_id, .. }
            | WorkflowUiEvent::RunFinished { run_id, .. } => {
                self.workflow_index.get(run_id).copied()
            }
        };
        let changed = match event {
            WorkflowUiEvent::RunStarted {
                run_id,
                name,
                class,
            } => {
                self.flush_text();
                let card = block::WorkflowCard {
                    run_id: ui_safe_text(&run_id),
                    name: ui_safe_text(&name),
                    class: ui_safe_text(&class),
                    status: block::WorkflowStatus::Planning,
                    tasks: Vec::new(),
                    dropped: 0,
                    duplicates_removed: 0,
                    invalid_removed: 0,
                    execution_mode: crate::runtime::WorkflowExecutionModeUi::Direct,
                    fan_turn_budget: 0,
                    writer_turn_reserve: 0,
                    fan_wall_secs: 0,
                    writer_wall_reserve_secs: 0,
                    started: Instant::now(),
                    elapsed: None,
                    reason: None,
                    provider_attempts: 0,
                    turns: 0,
                    tokens: 0,
                    tool_calls: 0,
                    failed_tasks: 0,
                    skipped_tasks: 0,
                    open: true,
                };
                let block_id = self.push_block(block::BlockKind::Workflow(card));
                self.workflow_index.insert(run_id, block_id);
                false // push_block already recorded the visible update
            }
            WorkflowUiEvent::PlanReady {
                run_id,
                tasks,
                dropped,
                duplicates_removed,
                invalid_removed,
                execution_mode,
                fan_turn_budget,
                writer_turn_reserve,
                fan_wall_secs,
                writer_wall_reserve_secs,
            } => {
                if let Some(card) = self.workflow_card_mut(&run_id) {
                    card.tasks = tasks
                        .into_iter()
                        .map(|task| block::WorkflowTaskCard {
                            id: task.id,
                            label: ui_safe_text(&task.label),
                            status: block::WorkflowTaskStatus::Queued,
                            started: None,
                            elapsed: None,
                            turns: 0,
                            tokens: 0,
                            tool_calls: 0,
                            turn_budget: 0,
                            sub_run: None,
                            activity: None,
                            summary_preview: None,
                            error_preview: None,
                        })
                        .collect();
                    card.dropped = dropped;
                    card.duplicates_removed = duplicates_removed;
                    card.invalid_removed = invalid_removed;
                    card.execution_mode = execution_mode;
                    card.fan_turn_budget = fan_turn_budget;
                    card.writer_turn_reserve = writer_turn_reserve;
                    card.fan_wall_secs = fan_wall_secs;
                    card.writer_wall_reserve_secs = writer_wall_reserve_secs;
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::PhaseChanged { run_id, phase } => {
                if let Some(card) = self.workflow_card_mut(&run_id) {
                    card.status = match phase {
                        WorkflowPhaseUi::Planning => block::WorkflowStatus::Planning,
                        WorkflowPhaseUi::Exploring => block::WorkflowStatus::Exploring,
                        WorkflowPhaseUi::Synthesizing => block::WorkflowStatus::Synthesizing,
                        WorkflowPhaseUi::Writing => block::WorkflowStatus::Writing,
                        WorkflowPhaseUi::Direct => block::WorkflowStatus::Direct,
                    };
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::AgentStarted {
                run_id,
                agent_id,
                sub_run,
                turn_budget,
            } => {
                if let Some(card) = self.workflow_card_mut(&run_id)
                    && let Some(task) = card.tasks.iter_mut().find(|task| task.id == agent_id)
                {
                    task.status = block::WorkflowTaskStatus::Running;
                    task.started = Some(Instant::now());
                    task.sub_run = Some(ui_safe_text(&sub_run));
                    task.turn_budget = turn_budget;
                    task.activity = Some("starting read-only investigation".into());
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::AgentActivity {
                run_id,
                agent_id,
                activity,
            } => {
                if let Some(card) = self.workflow_card_mut(&run_id)
                    && let Some(task) = card.tasks.iter_mut().find(|task| task.id == agent_id)
                    && task.status == block::WorkflowTaskStatus::Running
                {
                    task.activity = Some(ui_safe_text(&activity));
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::AgentFinished {
                run_id,
                agent_id,
                outcome,
                turns,
                tokens,
                tool_calls,
                elapsed_ms,
                summary_preview,
                error_preview,
            } => {
                if let Some(card) = self.workflow_card_mut(&run_id)
                    && let Some(task) = card.tasks.iter_mut().find(|task| task.id == agent_id)
                {
                    task.status = match outcome {
                        WorkflowAgentOutcomeUi::Done => block::WorkflowTaskStatus::Done,
                        WorkflowAgentOutcomeUi::Failed => block::WorkflowTaskStatus::Failed,
                        WorkflowAgentOutcomeUi::Interrupted => {
                            block::WorkflowTaskStatus::Interrupted
                        }
                        WorkflowAgentOutcomeUi::SkippedBudget => {
                            block::WorkflowTaskStatus::SkippedBudget
                        }
                        WorkflowAgentOutcomeUi::NotStarted => block::WorkflowTaskStatus::NotStarted,
                    };
                    task.elapsed = Some(Duration::from_millis(elapsed_ms));
                    task.turns = turns;
                    task.tokens = tokens;
                    task.tool_calls = tool_calls;
                    task.activity = None;
                    task.summary_preview = summary_preview.map(|text| ui_safe_text(&text));
                    task.error_preview = error_preview.map(|text| ui_safe_text(&text));
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::RunFinished {
                run_id,
                outcome,
                reason,
                elapsed_ms,
                provider_attempts,
                turns,
                tokens,
                tool_calls,
                failed_tasks,
                skipped_tasks,
            } => {
                let changed = if let Some(card) = self.workflow_card_mut(&run_id) {
                    card.status = match outcome {
                        WorkflowRunOutcomeUi::Done => block::WorkflowStatus::Done,
                        WorkflowRunOutcomeUi::Degraded => block::WorkflowStatus::Degraded,
                        WorkflowRunOutcomeUi::BudgetExhausted => {
                            block::WorkflowStatus::BudgetExhausted
                        }
                        WorkflowRunOutcomeUi::Stuck => block::WorkflowStatus::Stuck,
                        WorkflowRunOutcomeUi::Failed => block::WorkflowStatus::Failed,
                        WorkflowRunOutcomeUi::Stopped => block::WorkflowStatus::Stopped,
                    };
                    card.elapsed = Some(Duration::from_millis(elapsed_ms));
                    card.reason = reason.map(|text| ui_safe_text(&text));
                    card.provider_attempts = provider_attempts;
                    card.turns = turns;
                    card.tokens = tokens;
                    card.tool_calls = tool_calls;
                    card.failed_tasks = failed_tasks;
                    card.skipped_tasks = skipped_tasks;
                    for task in &mut card.tasks {
                        if matches!(
                            task.status,
                            block::WorkflowTaskStatus::Queued | block::WorkflowTaskStatus::Running
                        ) {
                            if task.status == block::WorkflowTaskStatus::Running {
                                task.elapsed = task
                                    .started
                                    .map(|started| started.elapsed())
                                    .or(Some(Duration::ZERO));
                            }
                            // Missing terminal evidence is an observation gap, never an inferred
                            // skip/interruption. The card stays open and names the uncertainty.
                            task.status = block::WorkflowTaskStatus::Unknown;
                            task.error_preview = Some("terminal evidence unavailable".into());
                        }
                    }
                    // Successful runs collapse to one calm summary; anything exceptional remains
                    // open so failure/skip evidence cannot disappear behind progressive disclosure.
                    card.open = outcome != WorkflowRunOutcomeUi::Done
                        || card
                            .tasks
                            .iter()
                            .any(|task| task.status != block::WorkflowTaskStatus::Done);
                    true
                } else {
                    false
                };
                self.workflow_index.remove(&run_id);
                changed
            }
        };
        if changed {
            let changed_index = existing_block_id.and_then(|block_id| {
                self.transcript
                    .iter()
                    .position(|block| block.id == block_id)
            });
            if let Some(block) = changed_index.and_then(|index| self.transcript.get_mut(index)) {
                Arc::make_mut(block).touch();
            }
            self.mark_transcript_changed_from(changed_index.unwrap_or(0));
            self.autoscroll();
        }
    }
}
