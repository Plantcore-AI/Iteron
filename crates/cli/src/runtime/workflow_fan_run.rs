use super::*;

impl Agent {
    /// Execute the built-in read-only fan through the same [`iteron_workflow::WorkflowEngine`] and
    /// [`KernelSpawner`] used by user-authored workflows. The parent remains outside the engine,
    /// pumps operator control while it joins, records the frozen compatibility stream, merges child
    /// ledgers, and then performs the deterministic reduce + sole-writer continuation itself.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) async fn run_workflow_fan(
        &mut self,
        workflow_run_id: &str,
        root_task: &str,
        class: iteron_agents::TaskClass,
        tasks: &[iteron_agents::AgentTask],
        aggregate: &Budget,
        workflow_state: &mut WorkflowRunState,
    ) -> Result<FanRun, KernelError> {
        let fan_breadth = self.execution_policy.fan_breadth.unwrap_or(0);
        let worker_min_turns = self.execution_policy.worker_min_turns.unwrap_or(u32::MAX);
        let active_workers = tasks
            .len()
            .min(fan_breadth)
            .min((aggregate.max_turns / worker_min_turns.max(1)) as usize);
        if active_workers == 0 {
            return Ok(FanRun::Completed(
                tasks
                    .iter()
                    .map(|task| iteron_agents::Summary {
                        idx: task.id,
                        assigned_question: task.objective.clone(),
                        outcome: iteron_agents::SummaryOutcome::Skipped,
                        text: "[fan worker skipped: aggregate turn budget reserved elsewhere]"
                            .into(),
                    })
                    .collect(),
            ));
        }
        let route = self
            .selected_route
            .as_ref()
            .map(|selected| selected.route.clone())
            .ok_or(KernelError::InvalidRoute(
                "workflow fan has no selected parent route",
            ))?;
        let budget_slices = fan_budget_slices(aggregate, active_workers, self.effective_max_usd());
        let child_ledgers = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let child_outcomes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cx = self.kernel_spawner_context(&route, workflow_run_id);
        cx.budget_slices = Some(budget_slices.clone());
        cx.child_ledgers = Some(child_ledgers.clone());
        cx.child_outcomes = Some(child_outcomes.clone());
        let workflow_budget = cx.budget.clone();
        let spawner = std::sync::Arc::new(KernelSpawner::new(cx));
        let child_run_ids = (0..active_workers)
            .map(|ordinal| spawner.run_id_for_ordinal(ordinal as u64).0)
            .collect::<Vec<_>>();

        let workflows_dir = self.runtime_state_dir.join("subagents").join("workflows");
        let args = serde_json::json!({
            "tasks": tasks[..active_workers]
                .iter()
                .map(|task| serde_json::json!({
                    "label": task.objective,
                    "agentType": task.agent_type,
                    "prompt": ultracode_investigator_prompt(root_task, class, task),
                }))
                .collect::<Vec<_>>(),
        });
        let collaboration = iteron_workflow::CollaborationStrategy::select_with(
            self.collaboration.as_ref(),
            &iteron_workflow::CollaborationObservation {
                version: iteron_workflow::COLLABORATION_SLOT_VERSION,
                active_workers,
                max_concurrency: fan_concurrency_permits(active_workers),
            },
            CapabilitySet::only(Capability::ReadOnly).intersect(self.authority_ceiling),
        )
        .map_err(|error| KernelError::WorkflowEngine(format!("collaboration refused: {error}")))?;
        let limits = iteron_workflow::RunLimits::new(collaboration.concurrency, active_workers)
            .and_then(|limits| workflow_spawner::governed_workflow_limits(&workflow_budget, limits))
            .map_err(|reason| KernelError::WorkflowEngine(reason.into()))?;
        let spec = iteron_workflow::RunSpec::new(ULTRACODE_FAN_SCRIPT)
            .with_args(args.clone())
            .with_run_id(iteron_workflow::RunId::new(workflow_run_id))
            .with_workflows_dir(workflows_dir.clone())
            .with_limits(limits)
            // The built-in fan runs on engine-default policy, which already reassigns on a definite
            // negative; carry the profile so its recovery artifact reaches that path too.
            .with_tunables_profile(self.tunables_profile());
        crate::workflow::persist_inputs(
            &workflows_dir,
            &crate::workflow::RunManifest {
                run_id: workflow_run_id.to_string(),
                name: "ultracode".into(),
                args,
                provider_id: route.provider_id,
                model: route.model_id,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_secs())
                    .unwrap_or(0),
            },
            ULTRACODE_FAN_SCRIPT,
        )
        .map_err(|error| {
            KernelError::WorkflowEngine(safe_agent_refusal(&format!(
                "cannot persist built-in workflow inputs: {error}"
            )))
        })?;

        self.workflow_progress(crate::workflow::WorkflowRunUiEvent::Started {
            run_id: workflow_run_id.to_string(),
            name: "ultracode".into(),
            phases: vec!["exploring".into(), "reducing".into(), "writing".into()],
        });
        workflow_state.engine_started = true;
        for task in tasks {
            self.workflow_progress(crate::workflow::WorkflowRunUiEvent::Progress {
                run_id: workflow_run_id.to_string(),
                event: iteron_workflow::ProgressEvent::AgentQueued {
                    index: task.id + 1,
                    label: ui_workflow_label(&task.objective),
                    phase: Some("exploring".into()),
                    model: None,
                },
            });
        }

        // Parent-side spawn evidence is committed before the engine starts any provider effect.
        // The concrete spawner exposes the same deterministic identity calculation it will use.
        for (index, task) in tasks[..active_workers].iter().enumerate() {
            let sub_run = child_run_ids[index].clone();
            let spawn_seq = self.emit_durable_seq(
                TurnId(self.seq_turn),
                EventKind::SubagentSpawned {
                    sub_run: sub_run.clone(),
                    agent: task.agent_type.clone().unwrap_or_else(|| "generic".into()),
                },
            )?;
            self.emit_durable(
                TurnId(self.seq_turn),
                EventKind::WorkflowV2 {
                    version: iteron_protocol::WorkflowEventVersion::V2,
                    workflow_id: workflow_run_id.to_string(),
                    event: iteron_protocol::WorkflowEvent::ChildStarted {
                        task_id: task.id as u32,
                        sub_run: sub_run.clone(),
                        spawn_seq,
                        budget: budget_slices[index].clone(),
                    },
                },
            )?;
            self.ui(UiEvent::Workflow(WorkflowUiEvent::AgentStarted {
                run_id: workflow_run_id.to_string(),
                agent_id: task.id,
                sub_run,
                turn_budget: budget_slices[index].max_turns,
            }));
        }

        let mut summaries = Vec::with_capacity(tasks.len());
        for task in &tasks[active_workers..] {
            let detail = "writer-first budget reserve left no safe worker allocation";
            self.emit_durable(
                TurnId(self.seq_turn),
                EventKind::WorkflowV2 {
                    version: iteron_protocol::WorkflowEventVersion::V2,
                    workflow_id: workflow_run_id.to_string(),
                    event: iteron_protocol::WorkflowEvent::ChildFinished {
                        task_id: task.id as u32,
                        sub_run: None,
                        outcome: iteron_protocol::WorkflowChildOutcome::SkippedBudget,
                        metrics: Ledger::default().workflow_metrics(),
                        error_code: Some("not_admitted_budget".into()),
                        error_detail: Some(detail.into()),
                        summary_digest: None,
                        evidence_bytes: 0,
                    },
                },
            )?;
            self.ui(UiEvent::Workflow(WorkflowUiEvent::AgentFinished {
                run_id: workflow_run_id.to_string(),
                agent_id: task.id,
                outcome: WorkflowAgentOutcomeUi::SkippedBudget,
                turns: 0,
                tokens: 0,
                tool_calls: 0,
                elapsed_ms: 0,
                summary_preview: None,
                error_preview: Some(detail.into()),
            }));
            self.workflow_progress(crate::workflow::WorkflowRunUiEvent::Progress {
                run_id: workflow_run_id.to_string(),
                event: iteron_workflow::ProgressEvent::AgentFinished {
                    index: task.id + 1,
                    label: ui_workflow_label(&task.objective),
                    state: iteron_workflow::WorkflowState::Skipped,
                    tokens: 0,
                    tool_calls: 0,
                    duration_ms: 0,
                    result_preview: None,
                    last_tool_summary: None,
                    error: Some(detail.into()),
                },
            });
            workflow_state.observe(WorkflowAgentOutcomeUi::SkippedBudget);
            summaries.push(iteron_agents::Summary {
                idx: task.id,
                assigned_question: task.objective.clone(),
                outcome: iteron_agents::SummaryOutcome::Skipped,
                text: "[fan worker skipped: aggregate turn budget reserved elsewhere]".into(),
            });
        }

        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel(
            iteron_tunables::param_integer(
                "cli.runtime.workflow_fan_progress_capacity",
                256usize,
            )
            .max(1),
        );
        let channel_sink: std::sync::Arc<dyn iteron_workflow::ProgressSink> =
            std::sync::Arc::new(WorkflowProgressChannel { tx: progress_tx });
        let sink: std::sync::Arc<dyn iteron_workflow::ProgressSink> =
            match self.workflow_progress_tx.clone() {
                Some(tx) => std::sync::Arc::new(crate::workflow::FanoutProgressSink::new(vec![
                    channel_sink,
                    std::sync::Arc::new(crate::workflow::UiProgressSink::new(workflow_run_id, tx)),
                ])),
                None => channel_sink,
            };
        let handle = iteron_workflow::WorkflowEngine::launch(spec, spawner, sink);
        let mut terminals = vec![None; active_workers];
        const WORKFLOW_FAN_POLL: Duration = Duration::from_millis(25);
        let report = {
            let mut joined = Box::pin(handle.join());
            loop {
                while let Ok(event) = progress_rx.try_recv() {
                    self.observe_workflow_fan_progress(
                        workflow_run_id,
                        tasks,
                        &child_ledgers,
                        event,
                        &mut terminals,
                        workflow_state,
                    )?;
                }
                match tokio::time::timeout(
                    iteron_tunables::param_duration(
                        "cli.runtime.workflow_fan_run.workflow_fan_poll",
                        WORKFLOW_FAN_POLL,
                    ),
                    &mut joined,
                )
                .await
                {
                    Ok(report) => break report,
                    Err(_) => {
                        let _ = self.collect_inbound_ops(TurnId(self.seq_turn));
                        if self.requested_control().interrupts() {
                            handle.cancel();
                        }
                    }
                }
            }
        };
        while let Ok(event) = progress_rx.try_recv() {
            self.observe_workflow_fan_progress(
                workflow_run_id,
                tasks,
                &child_ledgers,
                event,
                &mut terminals,
                workflow_state,
            )?;
        }
        let report = report
            .map_err(|error| KernelError::WorkflowEngine(safe_agent_refusal(&error.to_string())))?;
        if let Err(error) =
            crate::workflow::persist_result(&workflows_dir, workflow_run_id, &report)
        {
            self.emit(
                TurnId(self.seq_turn),
                EventKind::Notice {
                    text: format!(
                        "ultracode: cannot persist workflow result for {workflow_run_id}: {error}"
                    ),
                },
            );
        }

        let reports = if report.stopped {
            vec![None; active_workers]
        } else {
            let reports: Vec<Option<String>> = serde_json::from_value(report.value.clone())
                .map_err(|error| {
                    KernelError::WorkflowEngine(safe_agent_refusal(&format!(
                        "built-in workflow returned an invalid result: {error}"
                    )))
                })?;
            if reports.len() != active_workers {
                return Err(KernelError::WorkflowEngine(
                    "built-in workflow returned the wrong report count".into(),
                ));
            }
            reports
        };

        let mut ledgers = std::mem::take(&mut *child_ledgers.lock().unwrap());
        ledgers.sort_by_key(|(ordinal, _)| *ordinal);
        let mut ledgers_by_ordinal: Vec<Option<Ledger>> = std::iter::repeat_with(|| None)
            .take(active_workers)
            .collect();
        for (ordinal, ledger) in ledgers {
            if let Some(slot) = ledgers_by_ordinal.get_mut(ordinal as usize) {
                *slot = Some(ledger);
            }
        }
        let mut outcomes = std::mem::take(&mut *child_outcomes.lock().unwrap());
        outcomes.sort_by_key(|(ordinal, _)| *ordinal);
        let mut outcomes_by_ordinal: Vec<Option<Result<Outcome, String>>> =
            std::iter::repeat_with(|| None)
                .take(active_workers)
                .collect();
        for (ordinal, outcome) in outcomes {
            if let Some(slot) = outcomes_by_ordinal.get_mut(ordinal as usize) {
                *slot = Some(outcome);
            }
        }

        for (index, task) in tasks[..active_workers].iter().enumerate() {
            let terminal = terminals[index]
                .clone()
                .unwrap_or_else(|| EngineAgentTerminal {
                    state: iteron_workflow::WorkflowState::Error,
                    error: Some(if report.stopped {
                        "investigator stopped before returning a report".into()
                    } else {
                        "workflow engine omitted the investigator terminal".into()
                    }),
                });
            if terminals[index].is_none() {
                workflow_state.observe(if report.stopped {
                    WorkflowAgentOutcomeUi::Interrupted
                } else {
                    WorkflowAgentOutcomeUi::Failed
                });
            }
            let text = reports[index]
                .as_deref()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(|text| bounded_child_report(self.execution_policy, text));
            let done = terminal.state == iteron_workflow::WorkflowState::Done && text.is_some();
            let child_terminal = outcomes_by_ordinal[index].take();
            let drained = matches!(child_terminal.as_ref(), Some(Ok(Outcome::Drained)));
            let interrupted =
                report.stopped || matches!(child_terminal.as_ref(), Some(Ok(Outcome::Interrupted)));
            let (summary_outcome, child_outcome, error_code, error_detail, summary_text) = if done {
                (
                    iteron_agents::SummaryOutcome::Done,
                    iteron_protocol::WorkflowChildOutcome::Done,
                    None,
                    None,
                    text.unwrap(),
                )
            } else if drained {
                (
                    iteron_agents::SummaryOutcome::Failed,
                    iteron_protocol::WorkflowChildOutcome::Drained,
                    Some("operator_drain".into()),
                    Some("investigator drained after a durable checkpoint".into()),
                    "[fan worker drained]".into(),
                )
            } else if interrupted {
                (
                    iteron_agents::SummaryOutcome::Failed,
                    iteron_protocol::WorkflowChildOutcome::Interrupted,
                    Some("operator_stop".into()),
                    Some("investigator interrupted at a safe point".into()),
                    "[fan worker interrupted]".into(),
                )
            } else {
                let (code, typed_detail) = match child_terminal {
                    Some(Ok(Outcome::BudgetExhausted(_))) => (
                        "child_budget_exhausted",
                        Some("investigator exhausted its bounded turn or wall budget".into()),
                    ),
                    Some(Ok(Outcome::Stuck)) => (
                        "child_tool_error_limit",
                        Some("investigator reached the consecutive tool-error limit".into()),
                    ),
                    Some(Ok(Outcome::HarnessError)) => (
                        "child_harness_error",
                        Some("investigator stopped on a harness error".into()),
                    ),
                    Some(Err(detail)) => ("child_kernel_error", Some(detail)),
                    _ => ("child_workflow_error", None),
                };
                let detail = typed_detail
                    .or_else(|| terminal.error.clone())
                    .unwrap_or_else(|| "investigator completed without a report".into());
                (
                    iteron_agents::SummaryOutcome::Failed,
                    iteron_protocol::WorkflowChildOutcome::Failed,
                    Some(code.into()),
                    Some(detail.clone()),
                    format!("[subagent error: {detail}]"),
                )
            };
            let ledger = ledgers_by_ordinal[index].take().unwrap_or_default();
            let metrics = ledger.workflow_metrics();
            let summary_digest = done.then(|| sha256_hex(&summary_text));
            self.emit_durable(
                TurnId(self.seq_turn),
                EventKind::WorkflowV2 {
                    version: iteron_protocol::WorkflowEventVersion::V2,
                    workflow_id: workflow_run_id.to_string(),
                    event: iteron_protocol::WorkflowEvent::ChildFinished {
                        task_id: task.id as u32,
                        sub_run: Some(child_run_ids[index].clone()),
                        outcome: child_outcome,
                        metrics,
                        error_code,
                        error_detail,
                        summary_digest,
                        evidence_bytes: summary_text.len().min(u32::MAX as usize) as u32,
                    },
                },
            )?;
            self.merge_child_ledger(&ledger);
            summaries.push(iteron_agents::Summary {
                idx: task.id,
                assigned_question: task.objective.clone(),
                outcome: summary_outcome,
                text: summary_text,
            });
        }
        summaries.sort_by_key(|summary| summary.idx);

        if report.stopped {
            if let Some(outcome) =
                self.collect_and_finish_requested_control(TurnId(self.seq_turn)).await?
            {
                return Ok(FanRun::Stopped(outcome));
            }
            return Ok(FanRun::Stopped(Outcome::Interrupted));
        }
        if let Some(outcome) = self.collect_and_finish_requested_control(TurnId(self.seq_turn)).await? {
            return Ok(FanRun::Stopped(outcome));
        }
        Ok(FanRun::Completed(summaries))
    }
}
