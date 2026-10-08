#![cfg(unix)]

use iteron_agents::{
    AgentActor, AgentController, AgentControllerConfig, AgentFileJournal, AgentTerminalObservation,
    AgentWorkflowChildBinding, AgentWorkflowTerminal, ControllerError,
};
use iteron_protocol::agent_control::{
    AgentBudgetV1, AgentCommandV1, AgentIdV1, AgentStateV1, AgentUsageV1,
};
use iteron_protocol::{Capability, CapabilitySet};
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicU64, Ordering};

fn budget(turns: u32) -> AgentBudgetV1 {
    AgentBudgetV1 {
        turns,
        tokens: u64::from(turns) * 1000,
        cost_microusd: u64::from(turns) * 1000,
        wall_ms: 60000,
    }
}
fn config() -> AgentControllerConfig {
    AgentControllerConfig {
        workspace_scope: "physical-accounting-separation".into(),
        root_capabilities: CapabilitySet::only(Capability::ReadOnly),
        root_budget: budget(10),
        max_agents: 4,
        max_pending_per_agent: 8,
    }
}

#[test]
fn known_physical_terminal_survives_actual_restart_while_unknown_accounting_retains_admission_quarantine()
 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let state = std::env::temp_dir().join(format!(
        "iteron-accounting-terminal-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    let mut owner =
        AgentController::open(AgentFileJournal::open(&state).unwrap(), config()).unwrap();
    let admitted = owner
        .spawn_workflow_child(
            AgentActor::Operator,
            "physical-child",
            AgentCommandV1::Spawn {
                parent_id: AgentIdV1(1),
                label: "physical-child".into(),
                task: "observe".into(),
                capabilities: CapabilitySet::only(Capability::ReadOnly),
                budget: budget(3),
                write_paths: Vec::new(),
            },
            AgentWorkflowChildBinding {
                workflow_id: "physical-task".into(),
                node_id: 1,
                attempt: 1,
                input_digest: "a".repeat(64),
                deadline_unix_ms: 60001,
                execution: None,
            },
            1,
        )
        .unwrap();
    owner
        .finish_turn_with_observation(
            admitted.claim.assigned_agent,
            admitted.lease.epoch,
            "physical process reaped; price observation unavailable",
            AgentUsageV1 {
                turns: 1,
                tokens: 12,
                cost_microusd: 0,
                wall_ms: 1,
            },
            AgentTerminalObservation {
                effects_known: true,
                accounting_known: false,
            },
            AgentWorkflowTerminal::Failed,
        )
        .unwrap();
    let before = owner.workflow_completion(&admitted.claim).unwrap().unwrap();
    assert!(before.effects_known);
    assert!(!before.accounting_known);
    assert_eq!(before.usage.turns, 1);
    let actual_id = admitted.claim.assigned_agent;
    assert!(matches!(
        owner
            .inspect(AgentActor::Operator, actual_id)
            .unwrap()
            .state,
        AgentStateV1::RecoveryRequired { .. }
    ));
    let revision = owner.revision();
    drop(owner);
    let mut reopened =
        AgentController::open(AgentFileJournal::open(&state).unwrap(), config()).unwrap();
    assert_eq!(reopened.revision(), revision);
    assert_eq!(
        reopened.workflow_completion(&admitted.claim).unwrap(),
        Some(before)
    );
    assert!(matches!(
        reopened.execute(
            AgentActor::Operator,
            "try-close",
            AgentCommandV1::Close {
                agent_id: actual_id
            }
        ),
        Err(ControllerError::RecoveryRequired)
    ));
    assert!(!matches!(
        reopened.begin_runtime_turn(actual_id, 2),
        Ok(Some(_))
    ));
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, actual_id)
            .unwrap()
            .usage
            .turns,
        1
    );
    drop(reopened);
    std::fs::remove_dir_all(state).unwrap();
}

#[test]
fn actual_journal_current_epoch_engine_binding_excludes_completed_task_history() {
    use iteron_agents::{AgentEngineExecution, AgentEngineOrigin, AgentEngineParentSource};
    use iteron_protocol::{Effort, RunId, TenantId};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let state = std::env::temp_dir().join(format!(
        "iteron-current-engine-epoch-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    let mut owner =
        AgentController::open(AgentFileJournal::open(&state).unwrap(), config()).unwrap();
    let tenant = TenantId("epoch-fixture".into());
    let parent_run = RunId("actual-host-parent".into());
    let parent = AgentEngineParentSource {
        tenant: tenant.0.clone(),
        run: parent_run.0.clone(),
        provider_scope_sha256: iteron_protocol::agent_cohort::provider_scope(&tenant, &parent_run),
    };
    owner
        .bind_provider_budget(AgentIdV1(1), &parent.provider_scope_sha256)
        .unwrap();
    let first_execution = AgentEngineExecution {
        profile: "mapper".into(),
        profile_digest: format!("sha256:{}", "b".repeat(64)),
        provider_id: "fixture-provider".into(),
        model_id: "fixture-model".into(),
        catalog_digest: format!("sha256:{}", "c".repeat(64)),
        capability_digest: format!("sha256:{}", "d".repeat(64)),
        effort: Effort::Low,
        origin: AgentEngineOrigin::WorkflowChild {
            parent: parent.clone(),
            workflow_id: "first-actual-workflow".into(),
            task_id: 1,
        },
        native_context: None,
    };
    let first = owner
        .spawn_workflow_child(
            AgentActor::Agent(AgentIdV1(1)),
            "first-engine-admission",
            AgentCommandV1::Spawn {
                parent_id: AgentIdV1(1),
                label: "same resident".into(),
                task: "first actual engine task".into(),
                capabilities: CapabilitySet::only(Capability::ReadOnly),
                budget: budget(3),
                write_paths: Vec::new(),
            },
            AgentWorkflowChildBinding {
                workflow_id: "first-actual-workflow".into(),
                node_id: 1,
                attempt: 1,
                input_digest: "a".repeat(64),
                deadline_unix_ms: 10_000,
                execution: Some(first_execution.clone()),
            },
            1_000,
        )
        .unwrap();
    let id = first.claim.assigned_agent;
    assert_eq!(
        owner
            .runtime_engine_execution(id, first.lease.epoch)
            .unwrap(),
        Some(first_execution.clone())
    );
    assert_eq!(
        owner.runtime_epoch_deadline(id, first.lease.epoch).unwrap(),
        10_000
    );
    owner
        .finish_turn_with_observation(
            id,
            first.lease.epoch,
            "controller task completed; no provider IO in this attribution fixture",
            AgentUsageV1 {
                turns: 0,
                tokens: 0,
                cost_microusd: 0,
                wall_ms: 1,
            },
            AgentTerminalObservation {
                effects_known: true,
                accounting_known: true,
            },
            AgentWorkflowTerminal::Succeeded,
        )
        .unwrap();
    let first_terminal = owner.workflow_completion(&first.claim).unwrap().unwrap();
    let mut second_execution = first_execution;
    second_execution.origin = AgentEngineOrigin::WorkflowChild {
        parent,
        workflow_id: "second-actual-workflow".into(),
        task_id: 2,
    };
    let second_claim = iteron_agents::AgentWorkflowClaim {
        workflow_id: "second-actual-workflow".into(),
        node_id: 2,
        attempt: 1,
        input_digest: "e".repeat(64),
        assigned_agent: id,
        task: "second actual engine task".into(),
        budget: AgentBudgetV1 {
            wall_ms: 20_000,
            ..budget(1)
        },
        deadline_unix_ms: 30_000,
        execution: Some(second_execution.clone()),
    };
    // A separate admitted node owns a new epoch while retaining the same lifetime profile/route.
    let second = owner
        .claim_workflow_task(second_claim.clone(), 5_000)
        .unwrap();
    assert_ne!(first.lease.epoch, second.epoch);
    assert_eq!(second.agent.agent_id, id);
    assert_eq!(
        owner.runtime_engine_execution(id, second.epoch).unwrap(),
        Some(second_execution.clone())
    );
    assert_eq!(
        owner.runtime_epoch_deadline(id, second.epoch).unwrap(),
        30_000
    );
    assert_eq!(
        owner
            .runtime_engine_execution(id, first.lease.epoch)
            .unwrap_err(),
        ControllerError::StaleEpoch
    );
    assert_eq!(
        owner.workflow_completion(&first.claim).unwrap(),
        Some(first_terminal.clone())
    );
    let revision = owner.revision();
    drop(owner);
    // Reopen the actual private file journal, not a reconstructed or caller-edited snapshot.
    let reopened =
        AgentController::open(AgentFileJournal::open(&state).unwrap(), config()).unwrap();
    assert_eq!(
        reopened.revision(),
        revision + 1,
        "real reopen durably quarantines the active epoch"
    );
    assert_eq!(
        reopened.runtime_engine_execution(id, second.epoch).unwrap(),
        Some(second_execution)
    );
    assert_eq!(
        reopened.runtime_epoch_deadline(id, second.epoch).unwrap(),
        30_000
    );
    assert_eq!(
        reopened.workflow_completion(&first.claim).unwrap(),
        Some(first_terminal)
    );
    assert_eq!(reopened.workflow_completion(&second_claim).unwrap(), None);
    assert_eq!(
        reopened.inspect(AgentActor::Operator, id).unwrap().state,
        AgentStateV1::RecoveryRequired {
            epoch: second.epoch
        }
    );
    drop(reopened);
    std::fs::remove_dir_all(state).unwrap();
}
