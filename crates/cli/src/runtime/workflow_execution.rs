//! Actual script-run launch, cancellation and terminal projection. The launcher owns detached
//! work; an in-turn lifetime owns its cancellation token and exact child accounting evidence.
use super::{
    KernelError, detached_workflow_receipt, kernel_dispatch_control::KernelDispatchControl,
    kernel_dispatch_journal::KernelDispatchJournal, stream_tool_events::StreamToolEvents,
    workflow_preparation::WorkflowPreparation, workflow_run_id_arg,
};
use iteron_protocol::{
    EventKind, LifecyclePayload, TurnId, WorkflowChildOutcome, WorkflowEvent, WorkflowEventVersion,
};
use std::{sync::Arc, time::Duration};

pub(super) struct WorkflowExecution {
    pub(super) deadline: Option<std::time::Instant>,
    pub(super) preparation: Result<WorkflowPreparation, String>,
    pub(super) launcher: Option<Arc<dyn crate::workflow::WorkflowLauncher>>,
    pub(super) progress: WorkflowProgressProjection,
}
pub(super) struct WorkflowProgressProjection {
    pub(super) sender: Option<tokio::sync::mpsc::Sender<crate::workflow::WorkflowRunUiEvent>>,
    pub(super) frontend: super::frontend::FrontendChannelHealth,
    pub(super) events: StreamToolEvents,
}
impl WorkflowProgressProjection {
    fn present(&self, event: crate::workflow::WorkflowRunUiEvent) {
        if let Some(sender) = &self.sender
            && let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = sender.try_send(event)
        {
            let count = self.frontend.workflow_saturated();
            if count.is_power_of_two() {
                self.events.emit(
                    "queue.overflow",
                    None,
                    LifecyclePayload {
                        count: Some(count),
                        reason_code: Some("runtime_workflow".into()),
                        ..Default::default()
                    },
                );
            }
        }
    }
}
impl WorkflowExecution {
    pub(super) async fn run(
        self,
        input: &serde_json::Value,
        turn: TurnId,
        journal: &mut KernelDispatchJournal<'_>,
        control: &mut KernelDispatchControl<'_>,
        events: &StreamToolEvents,
    ) -> Result<Result<String, String>, KernelError> {
        if let Some(run) = workflow_run_id_arg(input, "collect") {
            return Ok(collected(self.owner().collect(&run)));
        }
        if let Some(run) = workflow_run_id_arg(input, "cancel") {
            return Ok(collected(self.owner().cancel(&run)));
        }
        let mut preparation = match self.preparation {
            Ok(preparation) => preparation,
            Err(reason) => return Ok(Err(reason)),
        };
        let resume = workflow_run_id_arg(input, "resumeFromRunId");
        let resumed_input;
        let input = if let Some(run) = &resume {
            if input.get("name").is_some()
                || input.get("script").is_some()
                || input.get("scriptPath").is_some()
            {
                return Ok(Err(
                    "Workflow: resumeFromRunId cannot be combined with name/script/scriptPath"
                        .into(),
                ));
            }
            if !crate::workflow::valid_run_id(run) {
                return Ok(Err("Workflow: invalid run id".into()));
            }
            let Some(manifest) = crate::workflow::load_manifest(&preparation.workflows_dir, run)
            else {
                return Ok(Err("Workflow: persisted manifest unavailable".into()));
            };
            if manifest.run_id != *run {
                return Ok(Err("Workflow: mismatched persisted identity".into()));
            }
            let Some(script) = crate::workflow::load_script(&preparation.workflows_dir, run) else {
                return Ok(Err("Workflow: persisted script unavailable".into()));
            };
            resumed_input =
                serde_json::json!({"script":script,"args":manifest.args,"background":true});
            &resumed_input
        } else {
            input
        };
        preparation.turn = turn;
        let prepared = match preparation.prepare(input, resume.as_deref(), journal) {
            Ok(prepared) => prepared,
            Err(reason) => return Ok(Err(reason)),
        };
        let background_requested = prepared.background_requested;
        let controller = prepared.controller;
        let native_ledgers = prepared.native_ledgers;
        let prepared = prepared.prepared;
        let run_id = prepared.run_id.clone();
        let name = prepared.name.clone();
        let directory = prepared.workflows_dir.clone();
        let degraded = prepared.degraded.clone();
        notice(
            journal,
            events,
            turn,
            format!("Workflow `{name}` launched (run {run_id}); `iteron workflow list` tracks it"),
        );
        self.progress
            .present(crate::workflow::WorkflowRunUiEvent::Started {
                run_id: run_id.clone(),
                name: name.clone(),
                phases: prepared.declared_phases.clone(),
            });
        let handle = match crate::workflow::launch_prepared(self.launcher.as_ref(), prepared) {
            crate::workflow::Launched::Detached(run) => {
                return Ok(Ok(detached_workflow_receipt(&run)));
            }
            crate::workflow::Launched::InTurn(handle) => handle,
        };
        let mut lifetime = InTurnLifetime {
            handle: handle.clone(),
            settled: false,
        };
        let report = {
            let mut joined = Box::pin(handle.join());
            let mut cancelled_at = None;
            loop {
                if self
                    .deadline
                    .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                {
                    handle.cancel();
                    cancelled_at.get_or_insert_with(std::time::Instant::now);
                }
                if cancelled_at.is_some_and(|start| start.elapsed() >= Duration::from_secs(5)) {
                    return Err(KernelError::UnknownEffects { count: 1 });
                }
                match tokio::time::timeout(Duration::from_millis(25), &mut joined).await {
                    Ok(report) => break report,
                    Err(_) => {
                        if control.poll(journal, turn).interrupts() {
                            handle.cancel();
                            cancelled_at.get_or_insert_with(std::time::Instant::now);
                        }
                    }
                }
            }
        };
        // A report proves engine join, while each actual child separately proves cleanup.
        let known = controller.as_ref().map_or_else(
            || {
                native_ledgers
                    .lock()
                    .is_ok_and(|owner| owner.effects_known())
            },
            |children| children.effects_known(),
        );
        if !known {
            return Err(KernelError::UnknownEffects { count: 1 });
        }
        lifetime.settled = true;
        if let Some(children) = &controller {
            for (claim, receipt, terminal) in children.completed_ledgers()? {
                let task = u32::try_from(claim.node_id).map_err(|_| {
                    KernelError::ContextResolution("actual task identity overflow".into())
                })?;
                publish_child(
                    journal,
                    turn,
                    &run_id,
                    task,
                    receipt.run().0.clone(),
                    receipt.ledger(),
                    match terminal {
                        iteron_agents::AgentWorkflowTerminal::Succeeded => {
                            WorkflowChildOutcome::Done
                        }
                        iteron_agents::AgentWorkflowTerminal::Cancelled => {
                            WorkflowChildOutcome::Interrupted
                        }
                        iteron_agents::AgentWorkflowTerminal::Failed
                        | iteron_agents::AgentWorkflowTerminal::StoppedRecovery => {
                            WorkflowChildOutcome::Failed
                        }
                    },
                )?;
            }
        } else {
            let receipts = native_ledgers
                .lock()
                .map_err(|_| {
                    KernelError::ContextResolution(
                        "native accounting observation unavailable".into(),
                    )
                })?
                .take_known()
                .map_err(|reason| KernelError::ContextResolution(reason.into()))?;
            for receipt in receipts {
                let task = u32::try_from(receipt.ordinal()).map_err(|_| {
                    KernelError::ContextResolution("actual task identity overflow".into())
                })?;
                if receipt.tenant() != journal.tenant() {
                    return Err(KernelError::ContextResolution(
                        "native child tenant mismatch".into(),
                    ));
                }
                publish_child(
                    journal,
                    turn,
                    &run_id,
                    task,
                    receipt.run().0.clone(),
                    receipt.ledger(),
                    receipt.outcome(),
                )?;
            }
        }
        let report = match report {
            Ok(report) => report,
            Err(error) => {
                let reason = format!("Workflow run failed: {error}");
                let failed = crate::workflow::unreported_run(&run_id, &reason);
                let _ = crate::workflow::persist_result(&directory, &run_id, &failed);
                self.progress
                    .present(crate::workflow::WorkflowRunUiEvent::Finished {
                        run_id,
                        terminal: crate::workflow::WorkflowRunTerminal::Failed,
                    });
                return Ok(Err(reason));
            }
        };
        self.progress
            .present(crate::workflow::WorkflowRunUiEvent::Finished {
                run_id: run_id.clone(),
                terminal: if report.stopped {
                    crate::workflow::WorkflowRunTerminal::Cancelled
                } else {
                    crate::workflow::WorkflowRunTerminal::Completed
                },
            });
        if let Err(error) = crate::workflow::persist_result(&directory, &run_id, &report) {
            notice(
                journal,
                events,
                turn,
                format!("Workflow: cannot persist run result for {run_id}: {error}"),
            );
        }
        let summary =
            crate::workflow::run_result_summary(&name, &run_id, &report, &degraded.reasons());
        Ok(Ok(if background_requested {
            format!(
                "NOTE: background was requested but this run retained the turn's bounded accounting lifetime; the result below is complete.\n\n{summary}"
            )
        } else {
            summary
        }))
    }
    fn owner(&self) -> &dyn crate::workflow::WorkflowLauncher {
        self.launcher
            .as_ref()
            .map_or(&crate::workflow::InTurnWorkflowLauncher, |owner| {
                owner.as_ref()
            })
    }
}
fn publish_child(
    journal: &mut KernelDispatchJournal<'_>,
    turn: TurnId,
    workflow: &str,
    task: u32,
    run: String,
    ledger: &iteron_obs::Ledger,
    outcome: WorkflowChildOutcome,
) -> Result<(), KernelError> {
    journal.append(
        turn,
        EventKind::WorkflowV2 {
            version: WorkflowEventVersion::V2,
            workflow_id: workflow.into(),
            event: WorkflowEvent::ChildFinished {
                task_id: task,
                sub_run: Some(run),
                outcome,
                metrics: ledger.workflow_metrics(),
                error_code: None,
                error_detail: None,
                summary_digest: None,
                evidence_bytes: 0,
            },
        },
    )?;
    journal.merge_child(ledger);
    Ok(())
}
fn notice(
    journal: &mut KernelDispatchJournal<'_>,
    events: &StreamToolEvents,
    turn: TurnId,
    text: String,
) {
    journal.observation(turn, EventKind::Notice { text: text.clone() }, events);
    events.present(super::frontend_events::UiEvent::Notice(text));
}
fn collected(collected: crate::workflow::Collected) -> Result<String, String> {
    match collected {
        crate::workflow::Collected::Unknown(reason) => Ok(reason),
        crate::workflow::Collected::Running {
            run_id,
            name,
            elapsed_ms,
        } => Ok(format!(
            "Workflow `{name}` (run {run_id}) is still RUNNING after {}s. It has produced no result yet. Do other work and call Workflow({{\"collect\":\"{run_id}\"}}) again; do not treat this as an outcome.",
            elapsed_ms / 1000
        )),
        crate::workflow::Collected::Settled { summary } => Ok(summary),
        crate::workflow::Collected::Failed { run_id, error } => {
            Err(format!("Workflow run {run_id}: {error}"))
        }
    }
}
struct InTurnLifetime {
    handle: Arc<iteron_workflow::RunHandle>,
    settled: bool,
}
impl Drop for InTurnLifetime {
    fn drop(&mut self) {
        if !self.settled {
            self.handle.cancel();
        }
    }
}
