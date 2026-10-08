//! One actually admitted direct investigation. Native construction or the durable controller
//! owns the child; this execution owns its real parent intent, cancellation and terminal receipt.
use super::{
    KernelError, KernelSpawner, KernelSpawnerContext,
    controller_engine_children::ControllerEngineChildren,
    effect_descriptor::{effect_done_terminal, effect_failed_terminal},
    kernel_dispatch_control::KernelDispatchControl,
    kernel_dispatch_journal::KernelDispatchJournal,
    stream_tool_events::StreamToolEvents,
    workflow_spawner::direct::DirectChildIdentity,
};
use iteron_kernel::{effect_class::EffectClass, effects};
use iteron_obs::Ledger;
use iteron_protocol::{
    Capability, EventKind, LifecyclePayload, Outcome, RunId, TurnId, WorkflowChildOutcome,
    WorkflowEventVersion,
};
use iteron_workflow::AgentOutcome;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub(super) enum DirectChildWork {
    Native {
        context: Box<KernelSpawnerContext>,
        identity: DirectChildIdentity,
    },
    Controller(Arc<ControllerEngineChildren>),
    Refused(String),
}
pub(super) struct DirectChildExecution {
    pub(super) work: DirectChildWork,
}
pub(super) struct DirectChildInvocation<'a> {
    pub(super) turn: TurnId,
    pub(super) index: usize,
    pub(super) task: &'a str,
}
impl DirectChildExecution {
    pub(super) async fn run(
        self,
        invocation: DirectChildInvocation<'_>,
        journal: &mut KernelDispatchJournal<'_>,
        control: &mut KernelDispatchControl<'_>,
        events: &StreamToolEvents,
        mut hooks: super::hook_execution::HookExecutionScope<'_>,
    ) -> Result<super::kernel_child_accounting::KernelChildCompletion, KernelError> {
        let DirectChildInvocation { turn, index, task } = invocation;
        if let DirectChildWork::Refused(reason) = &self.work {
            return Ok(
                super::kernel_child_accounting::KernelChildCompletion::no_child(
                    Err(reason.clone()),
                ),
            );
        }
        let mut events = events.clone();
        if let DirectChildWork::Native { identity, .. } = &self.work {
            let child = iteron_protocol::SubagentId(identity.run.0.clone());
            events.correlation.subagent_id = Some(child.clone());
            hooks.correlation.subagent_id = Some(child);
        }
        events.emit("workflow.child_proposed", None, LifecyclePayload::default());
        if let super::hooks::HookDecision::Deny(reason) = journal
            .hook(hooks)
            .lifecycle("workflow.child_proposed")
            .await?
            .decision
        {
            return Ok(
                super::kernel_child_accounting::KernelChildCompletion::no_child(Err(format!(
                    "subagent was not started: {reason}"
                ))),
            );
        }
        let (mut native, controller, run) = match self.work {
            DirectChildWork::Refused(reason) => {
                return Ok(
                    super::kernel_child_accounting::KernelChildCompletion::no_child(Err(reason)),
                );
            }
            DirectChildWork::Native { context, identity } => {
                let run = identity.run.clone();
                if context.session_spawn_ledger.admit().is_err() {
                    return Ok(
                        super::kernel_child_accounting::KernelChildCompletion::no_child(Err(
                            "subagent was not started: session spawn allowance exhausted".into(),
                        )),
                    );
                }
                let mut child = match KernelSpawner::new(*context).build_direct_child(&identity) {
                    Ok(child) => child,
                    Err(reason) => {
                        return Ok(
                            super::kernel_child_accounting::KernelChildCompletion::no_child(Err(
                                reason,
                            )),
                        );
                    }
                };
                child.inherit_force_cancel(control.force());
                child.control.inherit_drain(control.drain());
                (Some(child), None, Some(run))
            }
            DirectChildWork::Controller(children) => (None, Some(children), None),
        };
        if let Some(run) = &run {
            journal.append(
                turn,
                EventKind::SubagentSpawned {
                    sub_run: run.0.clone(),
                    agent: "direct-investigator".into(),
                },
            )?;
        }
        let ordinal = journal.next_ordinal(turn, EffectClass::Subagent);
        let workspace = native
            .as_ref()
            .map(|child| child.workspace.clone())
            .unwrap_or_else(|| journal.workspace().to_owned());
        let ticket=journal.open(&workspace,turn,EffectClass::Subagent,ordinal,Capability::CodeExecuting,
            serde_json::json!({"sub_run":run.as_ref().map(|value|&value.0),"controller_child":controller.is_some()}))?;
        if run.is_some() {
            events.emit("workflow.child_started", None, LifecyclePayload::default());
        }
        let prompt = format!(
            "{task}\n\nReturn a concise summary with file:line references. Do not attempt to edit anything."
        );
        let stop = Arc::new(AtomicBool::new(false));
        let _stop_on_drop = StopOnDrop(stop.clone());
        control.child_stop(journal, turn, &stop);
        let (result, terminal, receipt): (
            Result<String, String>,
            WorkflowChildOutcome,
            Option<(RunId, Ledger)>,
        ) = if let Some(child) = native.as_mut() {
            child.inherit_interrupt(stop.clone());
            let mut execution = Box::pin(child.run_leaf(&prompt));
            let outcome = loop {
                match tokio::time::timeout(Duration::from_millis(25), &mut execution).await {
                    Ok(outcome) => break outcome,
                    Err(_) => control.child_stop(journal, turn, &stop),
                }
            };
            drop(execution);
            control.poll(journal, turn);
            let processes = child.settle_persistent_owned_processes().await;
            let policy = child.finalize_policy_run().is_ok();
            if !processes || !policy || !child.parent_effects_known() {
                journal.settle(
                    ticket,
                    effects::Settlement::Unknown(
                        "child cleanup or physical effect proof is unavailable".into(),
                    ),
                )?;
                return Err(KernelError::UnknownEffects { count: 1 });
            }
            let (result, terminal) =
                native_terminal(outcome, &child.last_assistant_text, child.execution_policy);
            let receipt = (
                child.rollout.run_id().clone(),
                std::mem::take(&mut child.ledger),
            );
            (result, terminal, Some(receipt))
        } else {
            let children = controller.as_ref().expect("controller work was selected");
            let node = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(KernelError::ContextResolution(
                    "direct child index overflow".into(),
                ))?;
            let mut execution = Box::pin(children.direct(prompt, node));
            let outcome = loop {
                match tokio::time::timeout(Duration::from_millis(25), &mut execution).await {
                    Ok(outcome) => break outcome,
                    Err(_) => {
                        if control.poll(journal, turn).interrupts() {
                            children.cancel_all();
                        }
                    }
                }
            };
            drop(execution);
            if !children.effects_known() {
                journal.settle(
                    ticket,
                    effects::Settlement::Unknown(
                        "child cleanup or physical effect proof is unavailable".into(),
                    ),
                )?;
                return Err(KernelError::UnknownEffects { count: 1 });
            }
            let receipt = None;
            let result = match outcome {
                AgentOutcome::Text { text, .. } => Ok(text),
                AgentOutcome::Null { reason } => {
                    Err(reason.unwrap_or_else(|| "child produced no report".into()))
                }
            };
            let terminal = if result.is_ok() {
                WorkflowChildOutcome::Done
            } else {
                WorkflowChildOutcome::Failed
            };
            (result, terminal, receipt)
        };
        let settlement = match &result {
            Ok(_) => effects::Settlement::Definite(effect_done_terminal(
                turn,
                EffectClass::Subagent,
                ordinal,
            )),
            Err(reason) => effects::Settlement::Definite(effect_failed_terminal(
                turn,
                EffectClass::Subagent,
                ordinal,
                reason,
            )),
        };
        journal.settle(ticket, settlement)?;
        let accounting = match receipt {
            Some((run, ledger)) => {
                super::kernel_child_accounting::ChildAccountingSource::DirectNative {
                    run,
                    ledger: Box::new(ledger),
                    summary: result.clone(),
                    outcome: terminal,
                }
            }
            None => super::kernel_child_accounting::ChildAccountingSource::DirectController {
                children: controller.expect("controller work was selected"),
                summary: result.clone(),
            },
        };
        Ok(super::kernel_child_accounting::KernelChildCompletion::with_child(result, accounting))
    }
}
fn native_terminal(
    outcome: Result<Outcome, KernelError>,
    summary: &str,
    policy: crate::runtime_tunables::execution_policy::ExecutionRuntimePolicy,
) -> (Result<String, String>, WorkflowChildOutcome) {
    match outcome {
        Ok(Outcome::Done) => {
            let report = super::bounded_child_report(policy, summary);
            if report.is_empty() {
                (
                    Err("subagent completed without a summary".into()),
                    WorkflowChildOutcome::Failed,
                )
            } else {
                (Ok(report), WorkflowChildOutcome::Done)
            }
        }
        Ok(Outcome::Interrupted) => (
            Err("subagent interrupted at a safe point".into()),
            WorkflowChildOutcome::Interrupted,
        ),
        Ok(Outcome::Drained) => (
            Err("subagent drained after a checkpoint".into()),
            WorkflowChildOutcome::Drained,
        ),
        Ok(other) => (
            Err(format!("subagent stopped: {other:?}")),
            WorkflowChildOutcome::Failed,
        ),
        Err(error) => (Err(error.public_summary()), WorkflowChildOutcome::Failed),
    }
}
pub(super) fn publish_direct_terminal(
    journal: &mut KernelDispatchJournal<'_>,
    events: &StreamToolEvents,
    turn: TurnId,
    run: RunId,
    ledger: &Ledger,
    result: &Result<String, String>,
    outcome: WorkflowChildOutcome,
) -> Result<(), KernelError> {
    let success = result.is_ok();
    journal.append(
        turn,
        EventKind::SubagentFinishedV2 {
            version: WorkflowEventVersion::V2,
            sub_run: run.0.clone(),
            outcome,
            metrics: ledger.workflow_metrics(),
            error_code: result.as_ref().err().map(|_| "child_failed".into()),
            error_detail: result.as_ref().err().cloned(),
            summary_digest: result
                .as_ref()
                .ok()
                .map(|text| format!("{:x}", Sha256::digest(text.as_bytes()))),
            evidence_bytes: result
                .as_ref()
                .ok()
                .map_or(0, |text| u32::try_from(text.len()).unwrap_or(u32::MAX)),
        },
    )?;
    journal.merge_child(ledger);
    let mut events = events.clone();
    events.correlation.subagent_id = Some(iteron_protocol::SubagentId(run.0));
    events.emit(
        if success {
            "workflow.child_completed"
        } else {
            "workflow.child_failed"
        },
        None,
        LifecyclePayload::default(),
    );
    Ok(())
}
struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
