//! Actual Git, native provider constructor, record writer and attached host control journeys.
use crate::app_server::{
    AppServerHandle, Control, ControlReply, ControlRequest, WorkspaceRewound, attach,
    navigation_agent,
};
use crate::runtime::Agent;
use iteron_protocol::{
    Capability, Event, EventKind, Seq, TurnId, Verdict,
    workspace_rewind::{
        RewindFilesV1, RewindScopeV1, RewindTargetV1, RewindUnrecordedV1, WorkspaceRewindCommandV1,
    },
};
use std::{path::PathBuf, process::Command};

struct Repository(PathBuf);
impl Repository {
    fn new(label: &str) -> Self {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let root =
            std::env::temp_dir().join(format!("iteron-host-rewind-{label}-{}", hex::encode(nonce)));
        std::fs::create_dir(&root).unwrap();
        let result = Command::new("git")
            .current_dir(&root)
            .args(["init", "-q"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        Self(root)
    }
    fn agent(&self) -> (Agent, RewindTargetV1) {
        std::fs::write(self.0.join("editable.txt"), "checkpoint bytes\n").unwrap();
        let mut agent = navigation_agent(&self.0);
        let at = agent.rollout.next_sequence();
        let snapshot = iteron_record::checkpoint_excluding_runtime_state(
            agent.rollout.run_id(),
            at,
            &self.0,
            &self.0.join(".iteron/runs"),
        )
        .unwrap();
        let source = agent
            .rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Checkpoint {
                    at,
                    tree_ref: snapshot.tree_ref,
                },
            })
            .unwrap();
        assert_eq!(source, at);
        let target = RewindTargetV1 {
            run_id: agent.rollout.run_id().clone(),
            seq: source,
        };
        std::fs::write(self.0.join("editable.txt"), "operator current bytes\n").unwrap();
        (agent, target)
    }
}
impl Drop for Repository {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
async fn control(handle: &AppServerHandle, control: Control) -> ControlReply {
    let (reply, received) = tokio::sync::oneshot::channel();
    handle
        .control
        .send(ControlRequest { control, reply })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30), received)
        .await
        .unwrap()
        .unwrap()
}
async fn rewind(
    handle: &AppServerHandle,
    target: RewindTargetV1,
    scope: RewindScopeV1,
) -> WorkspaceRewound {
    let current = handle.client.thread_snapshot_v1().unwrap();
    let result = control(
        handle,
        Control::WorkspaceRewind {
            command: WorkspaceRewindCommandV1::Apply {
                thread_id: current.thread_id,
                run_id: current.run_id,
                target,
                scope,
                unrecorded: RewindUnrecordedV1::Keep,
            },
            cancel: None,
        },
    )
    .await;
    let ControlReply::WorkspaceRewound(result) = result else {
        panic!("actual host rewind reply: {result:?}");
    };
    *result
}

#[tokio::test]
async fn conversation_only_is_actual_adoption_and_never_restores_an_existing_file_checkpoint() {
    let repo = Repository::new("conversation");
    let (agent, target) = repo.agent();
    let origin = target.run_id.clone();
    let attached = attach(agent, true, false).unwrap();
    let result = rewind(&attached.handle, target, RewindScopeV1::ConversationOnly).await;
    let execution = result.presentation.execution.unwrap();
    assert_eq!(execution.files, RewindFilesV1::NotRequested);
    assert!(execution.conversation_adopted);
    assert!(result.navigation.is_some());
    assert_eq!(
        std::fs::read_to_string(repo.0.join("editable.txt")).unwrap(),
        "operator current bytes\n"
    );
    assert_ne!(
        attached.handle.client.thread_snapshot_v1().unwrap().run_id,
        origin
    );
    let events = iteron_record::replay(
        &repo
            .0
            .join(".iteron/runs")
            .join(format!("{}.jsonl", origin.0)),
    )
    .unwrap();
    assert!(!events.iter().any(
        |event| matches!(&event.kind,EventKind::EffectIntent {tool,..} if tool=="workspace_restore")
    ));
    drop(attached.handle);
    attached.task.await.unwrap();
}

#[tokio::test]
async fn local_write_grant_cannot_restore_trust_files_and_named_grant_has_real_receipts() {
    let repo = Repository::new("gate-and-receipts");
    let (agent, target) = repo.agent();
    let origin = target.run_id.clone();
    let attached = attach(agent, true, false).unwrap();
    control(
        &attached.handle,
        Control::SetCapabilityRule {
            capability: Capability::ReversibleLocal,
            verdict: Verdict::Auto,
        },
    )
    .await;
    let refused = rewind(&attached.handle, target.clone(), RewindScopeV1::CodeOnly).await;
    let execution = refused.presentation.execution.unwrap();
    assert_eq!(execution.files, RewindFilesV1::NotStarted);
    assert!(execution.intent_seq.is_none());
    assert_eq!(
        std::fs::read_to_string(repo.0.join("editable.txt")).unwrap(),
        "operator current bytes\n"
    );
    control(
        &attached.handle,
        Control::SetToolRule {
            tool: "workspace_rewind:trust_mutating".into(),
            verdict: Verdict::Auto,
        },
    )
    .await;
    let result = rewind(&attached.handle, target, RewindScopeV1::CodeOnly).await;
    let execution = result.presentation.execution.unwrap();
    assert_eq!(execution.files, RewindFilesV1::Restored);
    assert!(!execution.conversation_adopted);
    assert_eq!(
        std::fs::read_to_string(repo.0.join("editable.txt")).unwrap(),
        "checkpoint bytes\n"
    );
    assert_eq!(
        attached.handle.client.thread_snapshot_v1().unwrap().run_id,
        origin
    );
    let (intent, safety, terminal) = (
        execution.intent_seq.unwrap(),
        execution.safety_checkpoint_seq.unwrap(),
        execution.terminal_seq.unwrap(),
    );
    assert!(intent.0 < safety.0 && safety.0 < terminal.0);
    let events = iteron_record::replay(
        &repo
            .0
            .join(".iteron/runs")
            .join(format!("{}.jsonl", origin.0)),
    )
    .unwrap();
    assert!(events.iter().any(|event| event.seq == intent
        && matches!(&event.kind,EventKind::EffectIntent {tool,..} if tool=="workspace_restore")));
    assert!(events.iter().any(|event| event.seq == safety
        && matches!(&event.kind,EventKind::Checkpoint {at,..} if *at==safety)));
    assert!(events.iter().any(|event| event.seq == terminal
        && matches!(&event.kind,EventKind::EffectDone {tool,..} if tool=="workspace_restore")));
    drop(attached.handle);
    attached.task.await.unwrap();
}

#[tokio::test]
async fn real_checkout_failure_reports_observed_safety_rollback_and_does_not_adopt() {
    let repo = Repository::new("rollback");
    let (agent, target) = repo.agent();
    std::fs::remove_file(repo.0.join("editable.txt")).unwrap();
    std::fs::create_dir(repo.0.join("editable.txt")).unwrap();
    std::fs::write(
        repo.0.join("editable.txt/operator.txt"),
        "retained directory bytes\n",
    )
    .unwrap();
    let attached = attach(agent, true, false).unwrap();
    control(
        &attached.handle,
        Control::SetCapabilityRule {
            capability: Capability::ReversibleLocal,
            verdict: Verdict::Auto,
        },
    )
    .await;
    control(
        &attached.handle,
        Control::SetToolRule {
            tool: "workspace_rewind:trust_mutating".into(),
            verdict: Verdict::Auto,
        },
    )
    .await;
    let result = rewind(
        &attached.handle,
        target.clone(),
        RewindScopeV1::CodeAndConversation,
    )
    .await;
    let execution = result.presentation.execution.unwrap();
    assert_eq!(execution.files, RewindFilesV1::RolledBack);
    assert!(!execution.conversation_adopted);
    assert!(execution.retained_child_run.is_some());
    assert!(execution.terminal_seq.is_some());
    assert_eq!(
        attached.handle.client.thread_snapshot_v1().unwrap().run_id,
        target.run_id
    );
    assert_eq!(
        std::fs::read_to_string(repo.0.join("editable.txt/operator.txt")).unwrap(),
        "retained directory bytes\n"
    );
    assert!(result.navigation.is_none());
    drop(attached.handle);
    attached.task.await.unwrap();
}

#[tokio::test]
async fn unavailable_target_and_safety_trees_produce_real_unknown_and_forbid_automatic_readmission()
{
    use crate::app_server::{
        session_factory::{PreparationOrigin, RewindPreparation, SessionFactory},
        wire,
    };
    use crate::runtime::workspace_rewind::RewindTerminal;
    let repo = Repository::new("unknown");
    let (mut agent, target) = repo.agent();
    let mut rules = iteron_protocol::PermissionRules::new();
    rules.allow_cap(Capability::ReversibleLocal);
    rules.set_tool("workspace_rewind:trust_mutating", Verdict::Auto);
    agent
        .transition_permission_rules(rules, iteron_protocol::RuntimePolicySource::Operator)
        .unwrap();
    let (handle, mut ends) = wire().unwrap();
    ends.events.bind_lifecycle_identity(
        iteron_protocol::SessionId("rewind-fixture".into()),
        agent.rollout.run_id().clone(),
    );
    let factory = SessionFactory::capture(&agent, &handle.client).unwrap();
    let scope = handle.client.thread_snapshot_v1().unwrap();
    let origin = PreparationOrigin {
        thread: scope.thread_id.clone(),
        run: scope.run_id.clone(),
        selection: crate::providers::ModelSelection {
            provider_id: "fixture-navigation".into(),
            model_id: "m".into(),
        },
        checkpoint: agent.tunables_checkpoint().unwrap().clone(),
    };
    let command = WorkspaceRewindCommandV1::Apply {
        thread_id: scope.thread_id,
        run_id: scope.run_id,
        target,
        scope: RewindScopeV1::CodeOnly,
        unrecorded: RewindUnrecordedV1::Keep,
    };
    let RewindPreparation::Apply(prepared) =
        factory.prepare_rewind(origin, command, None).await.unwrap()
    else {
        panic!("native preparation");
    };
    let mut ticket = agent
        .admit_workspace_rewind(prepared.snapshot().unwrap())
        .unwrap();
    let permit = ticket.take_permit().unwrap();
    assert!(
        ticket.take_permit().is_none(),
        "an admitted effect cannot mint a second physical dispatch"
    );
    let (authorized, safety) = (*prepared).create_safety(permit).await.unwrap();
    let mut safety = safety.unwrap();
    let snapshot = safety.clone();
    agent.publish_rewind_safety(&ticket, &mut safety).unwrap();
    std::fs::rename(
        repo.0.join(".git/objects"),
        repo.0.join(".git/objects-unavailable"),
    )
    .unwrap();
    let completed = authorized.restore(safety).await.unwrap();
    assert_eq!(completed.files, RewindFilesV1::ReconciliationNeeded);
    let terminal = agent
        .settle_workspace_rewind(ticket, RewindTerminal::ReconciliationNeeded)
        .unwrap();
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert!(events.iter().any(|event| event.seq == terminal
        && matches!(&event.kind,EventKind::EffectUnknown {tool,..} if tool=="workspace_restore")));
    assert!(iteron_kernel::effect_journal::kind_blocks_resume(
        "workspace_restore"
    ));
    assert!(
        agent.admit_workspace_rewind(&snapshot).is_err(),
        "unknown state cannot dispatch an automatic retry"
    );
    drop(completed);
    drop(factory);
    drop(handle);
    drop(ends);
    drop(agent);
}
