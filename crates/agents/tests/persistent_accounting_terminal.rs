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
