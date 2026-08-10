use super::*;

pub(super) fn workflow_panel_agent_state(
    state: core_workflow::events::WorkflowState,
) -> workflows_panel::AgentState {
    use core_workflow::events::WorkflowState;
    match state {
        WorkflowState::Queued => workflows_panel::AgentState::Queued,
        WorkflowState::Running => workflows_panel::AgentState::Running,
        WorkflowState::Done => workflows_panel::AgentState::Done,
        WorkflowState::Error => workflows_panel::AgentState::Failed,
        WorkflowState::Skipped => workflows_panel::AgentState::Skipped,
    }
}

pub(super) fn legacy_workflow_agent_state(
    status: block::WorkflowTaskStatus,
) -> workflows_panel::AgentState {
    match status {
        block::WorkflowTaskStatus::Queued | block::WorkflowTaskStatus::NotStarted => {
            workflows_panel::AgentState::Queued
        }
        block::WorkflowTaskStatus::Running => workflows_panel::AgentState::Running,
        block::WorkflowTaskStatus::Done => workflows_panel::AgentState::Done,
        block::WorkflowTaskStatus::Failed
        | block::WorkflowTaskStatus::Interrupted
        | block::WorkflowTaskStatus::Unknown => workflows_panel::AgentState::Failed,
        block::WorkflowTaskStatus::SkippedBudget => workflows_panel::AgentState::Skipped,
    }
}

pub(super) fn workflow_panel_runs(app: &App) -> Vec<workflows_panel::Run> {
    use std::collections::HashSet;

    let mut runs = Vec::new();
    let mut seen = HashSet::new();

    // Newest transcript runs become the leftmost tabs. The WorkflowEngine card wins over the
    // temporary native compatibility card when both describe the same migrated built-in run.
    for entry in app.transcript.iter().rev() {
        let block::BlockKind::WorkflowRun(card) = &entry.kind else {
            continue;
        };
        if !seen.insert(card.run_id.clone()) || runs.len() >= workflows_panel::MAX_RUNS {
            continue;
        }
        let owned = app.workflows_panel.owned(&card.run_id);
        let failed = card
            .agents
            .iter()
            .any(|agent| agent.state == core_workflow::events::WorkflowState::Error);
        let state = if card.finished {
            if failed {
                workflows_panel::RunState::Failed
            } else {
                workflows_panel::RunState::Done
            }
        } else {
            owned.map_or(
                workflows_panel::RunState::Running,
                workflows_panel::owned_state,
            )
        };
        let model = card
            .agents
            .iter()
            .find_map(|agent| agent.model.clone())
            .unwrap_or_default();
        let mut phases = Vec::new();
        for phase in &card.phases {
            let agents = card
                .agents
                .iter()
                .filter(|agent| agent.phase_index == phase.index)
                .map(|agent| {
                    let mut facts = Vec::new();
                    if let Some(kind) = &agent.agent_type {
                        facts.push(kind.clone());
                    }
                    if let Some(model) = &agent.model {
                        facts.push(model.clone());
                    }
                    if agent.tokens > 0 {
                        facts.push(format!("{} tok", agent.tokens));
                    }
                    if agent.tool_calls > 0 {
                        facts.push(format!("{} tools", agent.tool_calls));
                    }
                    workflows_panel::Agent {
                        label: agent.label.clone(),
                        state: workflow_panel_agent_state(agent.state),
                        meta: facts.join(" · "),
                        activity: agent
                            .last_tool_summary
                            .clone()
                            .or_else(|| agent.error.clone())
                            .or_else(|| agent.result_preview.clone()),
                    }
                })
                .collect();
            phases.push(workflows_panel::Phase {
                title: phase.title.clone(),
                agents,
            });
        }
        let ungrouped: Vec<_> = card
            .agents
            .iter()
            .filter(|agent| agent.phase_index == 0)
            .map(|agent| workflows_panel::Agent {
                label: agent.label.clone(),
                state: workflow_panel_agent_state(agent.state),
                meta: agent.model.clone().unwrap_or_default(),
                activity: agent
                    .last_tool_summary
                    .clone()
                    .or_else(|| agent.error.clone())
                    .or_else(|| agent.result_preview.clone()),
            })
            .collect();
        if !ungrouped.is_empty() || phases.is_empty() {
            phases.push(workflows_panel::Phase {
                title: "workflow".into(),
                agents: ungrouped,
            });
        }
        runs.push(workflows_panel::Run {
            run_id: card.run_id.clone(),
            name: card.name.clone(),
            model,
            state,
            elapsed_ms: card
                .started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            phases,
            can_kill: !card.finished
                && owned
                    .is_some_and(|run| run.status == crate::workflow::SupervisedRunStatus::Running),
            can_resume: card.finished,
        });
    }

    for entry in app.transcript.iter().rev() {
        let block::BlockKind::Workflow(card) = &entry.kind else {
            continue;
        };
        if !seen.insert(card.run_id.clone()) || runs.len() >= workflows_panel::MAX_RUNS {
            continue;
        }
        let state = match card.status {
            block::WorkflowStatus::Planning
            | block::WorkflowStatus::Exploring
            | block::WorkflowStatus::Synthesizing
            | block::WorkflowStatus::Writing
            | block::WorkflowStatus::Direct => workflows_panel::RunState::Running,
            block::WorkflowStatus::Done | block::WorkflowStatus::Degraded => {
                workflows_panel::RunState::Done
            }
            block::WorkflowStatus::Stopped | block::WorkflowStatus::BudgetExhausted => {
                workflows_panel::RunState::Stopped
            }
            block::WorkflowStatus::Stuck | block::WorkflowStatus::Failed => {
                workflows_panel::RunState::Failed
            }
        };
        let agents = card
            .tasks
            .iter()
            .map(|task| workflows_panel::Agent {
                label: task.label.clone(),
                state: legacy_workflow_agent_state(task.status),
                meta: format!("{} tok · {} tools", task.tokens, task.tool_calls),
                activity: task
                    .activity
                    .clone()
                    .or_else(|| task.error_preview.clone())
                    .or_else(|| task.summary_preview.clone()),
            })
            .collect();
        let terminal = card.status.is_terminal();
        let owned = app.workflows_panel.owned(&card.run_id);
        runs.push(workflows_panel::Run {
            run_id: card.run_id.clone(),
            name: card.name.clone(),
            model: String::new(),
            state,
            elapsed_ms: card
                .elapsed
                .unwrap_or_else(|| card.started.elapsed())
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            phases: vec![workflows_panel::Phase {
                title: card.class.clone(),
                agents,
            }],
            can_kill: !terminal
                && owned
                    .is_some_and(|run| run.status == crate::workflow::SupervisedRunStatus::Running),
            can_resume: terminal,
        });
    }

    // The supervisor can know a run a frame before its first progress event creates a card.
    for owned in app.workflows_panel.owned_runs() {
        if !seen.insert(owned.run_id.clone()) || runs.len() >= workflows_panel::MAX_RUNS {
            continue;
        }
        let mut agents = Vec::new();
        if owned.running_agents > 0 {
            agents.push(workflows_panel::Agent {
                label: format!("{} agent(s) in flight", owned.running_agents),
                state: workflows_panel::AgentState::Running,
                meta: String::new(),
                activity: None,
            });
        }
        if owned.finished_agents > 0 {
            agents.push(workflows_panel::Agent {
                label: format!("{} result(s) retained", owned.finished_agents),
                state: workflows_panel::AgentState::Done,
                meta: String::new(),
                activity: None,
            });
        }
        let state = workflows_panel::owned_state(owned);
        runs.push(workflows_panel::Run {
            run_id: owned.run_id.clone(),
            name: ui_safe_text(&owned.name),
            model: String::new(),
            state,
            elapsed_ms: owned.elapsed_ms,
            phases: vec![workflows_panel::Phase {
                title: "session owner".into(),
                agents,
            }],
            can_kill: state == workflows_panel::RunState::Running,
            can_resume: matches!(
                state,
                workflows_panel::RunState::Done | workflows_panel::RunState::Failed
            ),
        });
    }

    for restored in app.workflow_monitor.restored_runs() {
        if !seen.insert(restored.run_id.clone()) || runs.len() >= workflows_panel::MAX_RUNS {
            continue;
        }
        let state = match restored.status {
            "done" => workflows_panel::RunState::Done,
            "failed" => workflows_panel::RunState::Failed,
            "stopped" => workflows_panel::RunState::Stopped,
            "running" => workflows_panel::RunState::Running,
            _ => workflows_panel::RunState::Pending,
        };
        let agents = (restored.agents > 0)
            .then(|| workflows_panel::Agent {
                label: format!("{} recorded agent result(s)", restored.agents),
                state: if matches!(state, workflows_panel::RunState::Failed) {
                    workflows_panel::AgentState::Failed
                } else {
                    workflows_panel::AgentState::Done
                },
                meta: "durable journal".into(),
                activity: None,
            })
            .into_iter()
            .collect();
        runs.push(workflows_panel::Run {
            run_id: restored.run_id.clone(),
            name: crate::workflow::ui_safe_label(&restored.name),
            model: ui_safe_text(&restored.model),
            state,
            elapsed_ms: 0,
            phases: vec![workflows_panel::Phase {
                title: "durable history".into(),
                agents,
            }],
            can_kill: false,
            can_resume: !matches!(state, workflows_panel::RunState::Running),
        });
    }

    runs
}
