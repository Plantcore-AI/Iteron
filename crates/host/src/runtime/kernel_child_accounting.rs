//! Physical child execution and the subsequent accounting observation have separate lifetimes.
//! This consumes real owned ledgers/host handles only after the outer known tool terminal. Exact
//! pending/resolved WAL receipts guard a crash between physical completion and accounting fold.
use super::{
    KernelError, controller_engine_children::ControllerEngineChildren,
    kernel_dispatch_journal::KernelDispatchJournal, kernel_workflow_ledgers::KernelWorkflowLedgers,
    stream_tool_events::StreamToolEvents,
};
use iteron_obs::Ledger;
use iteron_protocol::{EffectId, EventKind, RunId, TurnId, WorkflowChildOutcome};
use std::sync::{Arc, Mutex};

pub(super) struct KernelChildCompletion {
    result: Result<String, String>,
    accounting: Option<ChildAccountingSource>,
}
impl KernelChildCompletion {
    pub(super) fn new(
        result: Result<String, String>,
        accounting: Option<ChildAccountingSource>,
    ) -> Self {
        Self {
            result,
            accounting: accounting.filter(ChildAccountingSource::has_admissions),
        }
    }
    pub(super) fn no_child(result: Result<String, String>) -> Self {
        Self::new(result, None)
    }
    pub(super) fn with_child(
        result: Result<String, String>,
        accounting: ChildAccountingSource,
    ) -> Self {
        Self::new(result, Some(accounting))
    }
    pub(super) fn into_parts(self) -> (Result<String, String>, Option<ChildAccountingSource>) {
        (self.result, self.accounting)
    }
}
pub(super) enum ChildAccountingSource {
    DirectNative {
        run: RunId,
        ledger: Box<Ledger>,
        summary: Result<String, String>,
        outcome: WorkflowChildOutcome,
    },
    DirectController {
        children: Arc<ControllerEngineChildren>,
        summary: Result<String, String>,
    },
    Workflow {
        run: String,
        controller: Option<Arc<ControllerEngineChildren>>,
        native: Arc<Mutex<KernelWorkflowLedgers>>,
    },
}
impl ChildAccountingSource {
    fn has_admissions(&self) -> bool {
        match self {
            Self::DirectNative { .. } => true,
            Self::DirectController { children, .. } => children.has_admissions(),
            Self::Workflow {
                controller: Some(children),
                ..
            } => children.has_admissions(),
            Self::Workflow { native, .. } => {
                native.lock().map_or(true, |owner| owner.has_admissions())
            }
        }
    }
    pub(super) fn begin(
        &self,
        journal: &mut KernelDispatchJournal<'_>,
        turn: TurnId,
        effect: &EffectId,
    ) -> Result<Result<(), &'static str>, KernelError> {
        journal.append(
            turn,
            EventKind::ChildAccountingPendingV1 {
                effect_id: effect.clone(),
            },
        )?;
        Ok(journal.begin_child_accounting(effect))
    }
    pub(super) fn publish(
        self,
        journal: &mut KernelDispatchJournal<'_>,
        events: &StreamToolEvents,
        turn: TurnId,
        effect: &EffectId,
    ) -> Result<(), KernelError> {
        match self {
            Self::DirectNative {
                run,
                ledger,
                summary,
                outcome,
            } => super::direct_child_execution::publish_direct_terminal(
                journal, events, turn, run, &ledger, &summary, outcome,
            )?,
            Self::DirectController { children, summary } => {
                let receipts = children.completed_ledgers()?;
                if receipts.len() != 1 {
                    return Err(KernelError::ContextResolution(
                        "direct accounting must name one exact admitted child".into(),
                    ));
                }
                let (_, receipt, terminal) = &receipts[0];
                if receipt.tenant() != journal.tenant() {
                    return Err(KernelError::ContextResolution(
                        "direct child tenant mismatch".into(),
                    ));
                }
                super::direct_child_execution::publish_direct_terminal(
                    journal,
                    events,
                    turn,
                    receipt.run().clone(),
                    receipt.ledger(),
                    &summary,
                    child_outcome(*terminal),
                )?;
            }
            Self::Workflow {
                run,
                controller: Some(children),
                ..
            } => {
                for (claim, receipt, terminal) in children.completed_ledgers()? {
                    if receipt.tenant() != journal.tenant() {
                        return Err(KernelError::ContextResolution(
                            "workflow child tenant mismatch".into(),
                        ));
                    }
                    let task = u32::try_from(claim.node_id).map_err(|_| {
                        KernelError::ContextResolution("actual task identity overflow".into())
                    })?;
                    super::workflow_execution::publish_child(
                        journal,
                        turn,
                        &run,
                        task,
                        receipt.run().0.clone(),
                        receipt.ledger(),
                        child_outcome(terminal),
                    )?;
                }
            }
            Self::Workflow { run, native, .. } => {
                let receipts = native
                    .lock()
                    .map_err(|_| {
                        KernelError::ContextResolution(
                            "native accounting observation unavailable".into(),
                        )
                    })?
                    .take_known()
                    .map_err(|reason| KernelError::ContextResolution(reason.into()))?;
                for receipt in receipts {
                    if receipt.tenant() != journal.tenant() {
                        return Err(KernelError::ContextResolution(
                            "native child tenant mismatch".into(),
                        ));
                    }
                    let task = u32::try_from(receipt.ordinal()).map_err(|_| {
                        KernelError::ContextResolution("actual task identity overflow".into())
                    })?;
                    super::workflow_execution::publish_child(
                        journal,
                        turn,
                        &run,
                        task,
                        receipt.run().0.clone(),
                        receipt.ledger(),
                        receipt.outcome(),
                    )?;
                }
            }
        }
        journal.append(
            turn,
            EventKind::ChildAccountingResolvedV1 {
                effect_id: effect.clone(),
            },
        )?;
        journal.resolve_child_accounting(effect)?;
        Ok(())
    }
}
fn child_outcome(terminal: iteron_agents::AgentWorkflowTerminal) -> WorkflowChildOutcome {
    match terminal {
        iteron_agents::AgentWorkflowTerminal::Succeeded => WorkflowChildOutcome::Done,
        iteron_agents::AgentWorkflowTerminal::Cancelled => WorkflowChildOutcome::Interrupted,
        iteron_agents::AgentWorkflowTerminal::Failed
        | iteron_agents::AgentWorkflowTerminal::StoppedRecovery => WorkflowChildOutcome::Failed,
    }
}
