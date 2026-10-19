//! Restore coordinator. Native stages own their physical exclusion; the resident host alone
//! writes intent/safety/terminal facts and then adopts the already prepared conversation.
#[cfg(test)]
mod tests;
use super::AdoptRun;
use super::session_factory::{
    NavigationPresentation, PreparationOrigin, RewindPreparation, SessionFactory,
    SubmissionExclusionLease,
};
use crate::runtime::{Agent, workspace_rewind::RewindTerminal};
use iteron_protocol::workspace_rewind::{
    RewindFilesV1, WorkspaceRewindCommandV1, WorkspaceRewindReplyV1,
};
use std::sync::{Arc, atomic::AtomicBool};

pub(super) enum RewindControlResult {
    Observed(WorkspaceRewindReplyV1),
    Adopt {
        native: Box<AdoptRun>,
        presentation: NavigationPresentation,
        admission: SubmissionExclusionLease,
        reply: WorkspaceRewindReplyV1,
    },
}
pub(super) fn origin(
    agent: &Agent,
    contract: &super::product_contract::ContractReader,
    command: &WorkspaceRewindCommandV1,
) -> Result<PreparationOrigin, String> {
    let scope = contract
        .snapshot()
        .ok_or("public session scope unavailable")?;
    if scope.run_id != *agent.rollout.run_id()
        || scope.thread_id != *command.thread_id()
        || scope.run_id != *command.run_id()
    {
        return Err("rewind belongs to a previous thread/run".into());
    }
    Ok(PreparationOrigin {
        thread: scope.thread_id,
        run: scope.run_id,
        checkpoint: agent
            .tunables_checkpoint()
            .map_err(|error| error.public_summary().to_owned())?
            .clone(),
        selection: crate::providers::ModelSelection {
            provider_id: iteron_provider::Provider::provider_instance_id(agent.provider.as_ref())
                .unwrap_or_default()
                .to_owned(),
            model_id: agent.model.clone(),
        },
    })
}
pub(super) async fn prepare(
    agent: &mut Agent,
    factory: &Arc<SessionFactory>,
    origin: PreparationOrigin,
    command: WorkspaceRewindCommandV1,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<RewindControlResult, String> {
    let mut prepared = match factory.prepare_rewind(origin, command, cancel).await? {
        RewindPreparation::Observed(reply) => return Ok(RewindControlResult::Observed(*reply)),
        RewindPreparation::Apply(prepared) => *prepared,
    };
    if prepared.is_cancelled() {
        prepared.reply_mut().execution.as_mut().expect("apply").reason=Some("rewind cancelled before host adoption or working-file mutation; any created branch is retained unselected".into());
        return finish(prepared, false);
    }
    let Some(snapshot) = prepared.snapshot() else {
        return finish(prepared, true);
    };
    let mut ticket = match agent.admit_workspace_rewind(snapshot) {
        Ok(ticket) => ticket,
        Err(error) => {
            let execution = prepared
                .reply_mut()
                .execution
                .as_mut()
                .expect("apply has execution projection");
            execution.files = RewindFilesV1::NotStarted;
            execution.reason = Some(match &error {
                crate::runtime::KernelError::EffectBoundary(reason) => reason.clone(),
                _ => error.public_summary().to_owned(),
            });
            return finish(prepared, false);
        }
    };
    let retained_child = prepared.retained_child();
    let mut fallback = prepared.reply_mut().clone();
    let intent = ticket.intent_sequence();
    fallback.execution.as_mut().expect("apply").intent_seq = Some(intent);
    prepared
        .reply_mut()
        .execution
        .as_mut()
        .expect("apply")
        .intent_seq = Some(intent);
    let permit = ticket
        .take_permit()
        .expect("one actual native dispatch per admitted restore");
    let (authorized, safety) = match prepared.create_safety(permit).await {
        Ok(result) => result,
        Err(_) => {
            let execution = fallback.execution.as_mut().expect("apply");
            execution.files = RewindFilesV1::ReconciliationNeeded;
            execution.retained_child_run = retained_child;
            execution.reason=Some("native safety capture has no observed result; working-file restore was not authorized to start".into());
            execution.terminal_seq = agent
                .settle_workspace_rewind(ticket, RewindTerminal::ReconciliationNeeded)
                .ok();
            return Ok(RewindControlResult::Observed(fallback));
        }
    };
    let mut safety = match safety {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            let mut prepared = authorized.into_prepared();
            let execution = prepared.reply_mut().execution.as_mut().expect("apply");
            execution.files = RewindFilesV1::NotStarted;
            execution.reason = Some(reason);
            execution.terminal_seq = agent
                .settle_workspace_rewind(ticket, RewindTerminal::NotStarted)
                .ok();
            return finish(prepared, false);
        }
    };
    let safety_seq = match agent.publish_rewind_safety(&ticket, &mut safety) {
        Ok(seq) => seq,
        Err(_) => {
            let mut prepared = authorized.into_prepared();
            let execution = prepared.reply_mut().execution.as_mut().expect("apply");
            execution.files = RewindFilesV1::NotStarted;
            execution.reason=Some("pre-restore safety journal barrier was not confirmed; no working-file restore began".into());
            // The failed writer barrier must not be followed by a success/selection claim.
            return finish(prepared, false);
        }
    };
    fallback
        .execution
        .as_mut()
        .expect("apply")
        .safety_checkpoint_seq = Some(safety_seq);
    let completed = match authorized.restore(safety).await {
        Ok(completed) => completed,
        Err(_) => {
            let execution = fallback.execution.as_mut().expect("apply");
            execution.files = RewindFilesV1::ReconciliationNeeded;
            execution.reason=Some("restore worker has no observed terminal; reconcile against the durable safety checkpoint".into());
            execution.terminal_seq = agent
                .settle_workspace_rewind(ticket, RewindTerminal::ReconciliationNeeded)
                .ok();
            return Ok(RewindControlResult::Observed(fallback));
        }
    };
    finish_restoration(agent, ticket, safety_seq, completed)
}

fn finish_restoration(
    agent: &mut Agent,
    ticket: crate::runtime::workspace_rewind::WorkspaceRewindTicket,
    safety_seq: iteron_protocol::Seq,
    completed: super::session_factory::CompletedRewind,
) -> Result<RewindControlResult, String> {
    let mut prepared = completed.prepared;
    let execution = prepared.reply_mut().execution.as_mut().expect("apply");
    execution.files = completed.files;
    execution.safety_checkpoint_seq = Some(safety_seq);
    let terminal = match completed.files {
        RewindFilesV1::Restored => RewindTerminal::Restored,
        RewindFilesV1::RolledBack => RewindTerminal::FailedAndRolledBack,
        RewindFilesV1::NotStarted | RewindFilesV1::NotRequested => RewindTerminal::NotStarted,
        RewindFilesV1::ReconciliationNeeded => RewindTerminal::ReconciliationNeeded,
    };
    let confirmed = match agent.settle_workspace_rewind(ticket, terminal) {
        Ok(seq) => {
            execution.terminal_seq = Some(seq);
            true
        }
        Err(_) => {
            execution.reason=Some("native result was observed but its durable terminal was not confirmed; conversation was not adopted".into());
            false
        }
    };
    if execution.reason.is_none() {
        execution.reason=match completed.files {
            RewindFilesV1::RolledBack=>Some("restore failed; the native safety rollback completed; conversation was not adopted".into()),
            RewindFilesV1::ReconciliationNeeded=>Some("restore and rollback do not have a confirmed native result; reconcile before retry".into()),
            RewindFilesV1::NotStarted=>Some("restore was cancelled before working-file mutation; conversation was not adopted".into()),
            _=>None,
        };
    }
    finish(
        prepared,
        confirmed && completed.files == RewindFilesV1::Restored,
    )
}
fn finish(
    prepared: super::session_factory::PreparedRewind,
    adopt: bool,
) -> Result<RewindControlResult, String> {
    let (reply, native, admission) = prepared.into_parts();
    if adopt && let Some((native, presentation)) = native {
        Ok(RewindControlResult::Adopt {
            native: Box::new(native),
            presentation,
            admission,
            reply,
        })
    } else {
        // Native work is finished; the already-created child remains an explicitly reported
        // unselected record, and the writer and exclusion leases are released here.
        Ok(RewindControlResult::Observed(reply))
    }
}
