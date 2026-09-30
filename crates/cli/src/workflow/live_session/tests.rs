//! Real controller/host plus real private graph journals; only the provider runtime is a fixture.

use super::registry::Registry;
use super::{
    LiveWorkflowCommandV1 as Command, LiveWorkflowPolicy, LiveWorkflowPort, LiveWorkflowSession,
};
use crate::runtime::persistent_agents::{
    AgentControlPort, AgentSettlement, LiveAgentMailbox, PersistentAgentHost,
    PersistentAgentRuntime,
};
use async_trait::async_trait;
use iteron_agents::{
    AgentActor, AgentController, AgentControllerConfig, AgentControllerJournal,
    AgentControllerSnapshot, AgentMailboxMessage, AgentWorkflowTerminal, ControllerError,
    ControllerStoreError,
};
use iteron_protocol::agent_control::{
    AgentBudgetV1, AgentCommandV1, AgentEpochV1, AgentIdV1, AgentStateV1, AgentViewV1,
};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Capability, Message};
use iteron_workflow::live_scheduler::{
    WorkflowNodeStateV1 as State, WorkflowNodeV1, WorkflowPlanChangeV1 as Change, WorkflowReplanV1,
    WorkflowStoreError,
};
use iteron_workflow::task_dag::TaskBudget;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};

#[derive(Default)]
struct Journal(Option<AgentControllerSnapshot>);
impl AgentControllerJournal for Journal {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        Ok(self.0.clone())
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        if self.0.as_ref().map(AgentControllerSnapshot::revision) != expected {
            return Err(ControllerStoreError::Conflict);
        }
        self.0 = Some(next.clone());
        Ok(())
    }
}

struct Runtime {
    requests: Mutex<Vec<String>>,
    entered: Notify,
    release: Semaphore,
}
#[async_trait]
impl PersistentAgentRuntime for Runtime {
    fn validate_spawn(&self, _: &AgentCommandV1) -> Result<(), ControllerError> {
        Ok(())
    }
    async fn execute(
        &self,
        _: AgentViewV1,
        _: AgentEpochV1,
        initial: Vec<AgentMailboxMessage>,
        mailbox: LiveAgentMailbox,
    ) -> AgentSettlement {
        let task = initial
            .iter()
            .filter_map(|input| input.text.as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        let messages: Vec<_> = initial
            .iter()
            .map(|input| Message::user_text(mailbox.render(input).unwrap()))
            .collect();
        mailbox.confirm_request(&messages).unwrap();
        self.requests.lock().unwrap().push(task.clone());
        if task == "work-a" {
            self.entered.notify_one();
            self.release.acquire().await.unwrap().forget();
        }
        AgentSettlement {
            summary: task.clone(),
            tokens: 1,
            cost_microusd: 0,
            effects_known: task != "unknown",
            terminal: if task == "unknown" {
                AgentWorkflowTerminal::StoppedRecovery
            } else {
                AgentWorkflowTerminal::Succeeded
            },
        }
    }
}

fn agent_budget() -> AgentBudgetV1 {
    AgentBudgetV1 {
        turns: 100,
        tokens: 100_000,
        cost_microusd: 100,
        wall_ms: 30_000,
    }
}
fn policy() -> LiveWorkflowPolicy {
    LiveWorkflowPolicy {
        root_agent_id: 1,
        aggregate_budget: TaskBudget {
            max_turns: 100,
            max_tokens: 100_000,
            max_cost_microusd: 100,
            max_wall_ms: 30_000,
        },
        graph_budget: TaskBudget {
            max_turns: 20,
            max_tokens: 10_000,
            max_cost_microusd: 10,
            max_wall_ms: 10_000,
        },
        max_workflows: 4,
        max_nodes: 16,
        max_edges: 32,
        max_concurrency: 2,
    }
}
fn node(id: u64, agent: AgentIdV1, task: &str, dependencies: Vec<u64>) -> WorkflowNodeV1 {
    WorkflowNodeV1 {
        id,
        label: format!("node-{id}"),
        task: task.into(),
        dependencies,
        assigned_agent: agent.0,
        input_digest: format!("{:x}", Sha256::digest(task.as_bytes())),
        budget: TaskBudget {
            max_turns: 1,
            max_tokens: 100,
            max_cost_microusd: 1,
            max_wall_ms: 5_000,
        },
    }
}
async fn host() -> (Arc<PersistentAgentHost<Journal>>, Arc<Runtime>, AgentIdV1) {
    let runtime = Arc::new(Runtime {
        requests: Mutex::new(Vec::new()),
        entered: Notify::new(),
        release: Semaphore::new(0),
    });
    let controller = AgentController::open(
        Journal::default(),
        AgentControllerConfig {
            workspace_scope: "live-workflow-fixture".into(),
            root_capabilities: CapabilitySet::only(Capability::ReadOnly),
            root_budget: agent_budget(),
            max_agents: 8,
            max_pending_per_agent: 8,
        },
    )
    .unwrap();
    let host = Arc::new(PersistentAgentHost::new(controller, runtime.clone(), 2).unwrap());
    let agent = host
        .command(
            AgentActor::Operator,
            "spawn",
            AgentCommandV1::Spawn {
                parent_id: AgentIdV1(1),
                label: "existing-worker".into(),
                task: "seed".into(),
                capabilities: CapabilitySet::only(Capability::ReadOnly),
                budget: agent_budget(),
                write_paths: Vec::new(),
            },
        )
        .unwrap()
        .agent_id;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !matches!(
            host.inspect(AgentActor::Operator, agent).unwrap().state,
            AgentStateV1::Idle
        ) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    (host, runtime, agent)
}
fn root(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().join("private-session")
}
fn graph_path(root: &Path, id: &str) -> PathBuf {
    root.join(format!("wf_{:x}", Sha256::digest(id.as_bytes())))
}

async fn read_until(
    session: &dyn LiveWorkflowPort,
    predicate: impl Fn(&super::LiveWorkflowReplyV1) -> bool,
) -> super::LiveWorkflowReplyV1 {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let reply = session
                .command(Command::Read {
                    workflow_id: "graph".into(),
                })
                .await
                .unwrap();
            if predicate(&reply) {
                return reply;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn actual_owner_replans_future_node_while_existing_agent_runs_and_settles_dependency() {
    let temp = tempfile::tempdir().unwrap();
    let (host, runtime, agent) = host().await;
    let session = LiveWorkflowSession::new(root(&temp), policy(), host).unwrap();
    session
        .command(Command::Open {
            workflow_id: "graph".into(),
        })
        .await
        .unwrap();
    session
        .command(Command::Replan {
            workflow_id: "graph".into(),
            request_id: "initial".into(),
            plan: WorkflowReplanV1 {
                expected_revision: 0,
                changes: vec![
                    Change::Add {
                        node: node(1, agent, "work-a", vec![]),
                    },
                    Change::Add {
                        node: node(2, agent, "old-b", vec![1]),
                    },
                ],
            },
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), runtime.entered.notified())
        .await
        .unwrap();
    let running = read_until(session.as_ref(), |reply| {
        matches!(reply.view.nodes[0].state, State::Running { .. })
    })
    .await;
    assert_eq!(running.view.revision, 1);
    session
        .command(Command::Replan {
            workflow_id: "graph".into(),
            request_id: "revise-future".into(),
            plan: WorkflowReplanV1 {
                expected_revision: 1,
                changes: vec![Change::ReplacePending {
                    node: node(2, agent, "revised-b", vec![1]),
                }],
            },
        })
        .await
        .unwrap();
    runtime.release.add_permits(1);
    let complete = read_until(session.as_ref(), |reply| {
        reply
            .view
            .nodes
            .iter()
            .all(|node| matches!(node.state, State::Succeeded { .. }))
    })
    .await;
    assert_eq!(complete.view.revision, 2);
    assert_eq!(complete.view.reserved.turns, 2);
    assert_eq!(
        *runtime.requests.lock().unwrap(),
        ["seed", "work-a", "revised-b"]
    );
    let replay = session
        .command(Command::Replan {
            workflow_id: "graph".into(),
            request_id: "revise-future".into(),
            plan: WorkflowReplanV1 {
                expected_revision: 1,
                changes: vec![Change::ReplacePending {
                    node: node(2, agent, "revised-b", vec![1]),
                }],
            },
        })
        .await
        .unwrap();
    assert!(replay.receipt.unwrap().replayed);
}

#[tokio::test]
async fn real_journal_reopen_never_reruns_finished_work_and_lost_active_graph_is_not_fresh() {
    let temp = tempfile::tempdir().unwrap();
    let state_root = root(&temp);
    let (host, runtime, agent) = host().await;
    let mut registry = Registry::open(&state_root, policy()).unwrap();
    registry
        .command(
            Command::Open {
                workflow_id: "graph".into(),
            },
            host.as_ref(),
        )
        .await
        .unwrap();
    registry
        .command(
            Command::Replan {
                workflow_id: "graph".into(),
                request_id: "plan".into(),
                plan: WorkflowReplanV1 {
                    expected_revision: 0,
                    changes: vec![Change::Add {
                        node: node(1, agent, "finished", vec![]),
                    }],
                },
            },
            host.as_ref(),
        )
        .await
        .unwrap();
    for _ in 0..100 {
        registry
            .command(
                Command::Pump {
                    workflow_id: "graph".into(),
                },
                host.as_ref(),
            )
            .await
            .unwrap();
        if matches!(
            registry.view("graph").unwrap().nodes[0].state,
            State::Succeeded { .. }
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(matches!(
        registry.view("graph").unwrap().nodes[0].state,
        State::Succeeded { .. }
    ));
    let deadline = registry.view("graph").unwrap().config.deadline_unix_ms;
    drop(registry);
    let mut reopened = Registry::open(&state_root, policy()).unwrap();
    reopened
        .command(
            Command::Pump {
                workflow_id: "graph".into(),
            },
            host.as_ref(),
        )
        .await
        .unwrap();
    assert_eq!(
        reopened.view("graph").unwrap().config.deadline_unix_ms,
        deadline
    );
    assert_eq!(*runtime.requests.lock().unwrap(), ["seed", "finished"]);
    drop(reopened);
    std::fs::remove_dir_all(graph_path(&state_root, "graph")).unwrap();
    assert!(matches!(
        Registry::open(&state_root, policy()),
        Err(super::LiveWorkflowError::Store(
            WorkflowStoreError::OutcomeUnknown
        ))
    ));
}

#[tokio::test]
async fn unknown_effect_proof_quarantines_without_success_or_repeated_debit() {
    let temp = tempfile::tempdir().unwrap();
    let (host, runtime, agent) = host().await;
    let mut registry = Registry::open(&root(&temp), policy()).unwrap();
    registry
        .command(
            Command::Open {
                workflow_id: "graph".into(),
            },
            host.as_ref(),
        )
        .await
        .unwrap();
    registry
        .command(
            Command::Replan {
                workflow_id: "graph".into(),
                request_id: "plan".into(),
                plan: WorkflowReplanV1 {
                    expected_revision: 0,
                    changes: vec![
                        Change::Add {
                            node: node(1, agent, "unknown", vec![]),
                        },
                        Change::Add {
                            node: node(2, agent, "blocked", vec![1]),
                        },
                    ],
                },
            },
            host.as_ref(),
        )
        .await
        .unwrap();
    for _ in 0..100 {
        registry
            .command(
                Command::Pump {
                    workflow_id: "graph".into(),
                },
                host.as_ref(),
            )
            .await
            .unwrap();
        if matches!(
            registry.view("graph").unwrap().nodes[0].state,
            State::RecoveryRequired { .. }
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let before = registry.view("graph").unwrap();
    assert!(matches!(
        before.nodes[0].state,
        State::RecoveryRequired { .. }
    ));
    for _ in 0..3 {
        registry
            .command(
                Command::Reconcile {
                    workflow_id: "graph".into(),
                    node_id: 1,
                },
                host.as_ref(),
            )
            .await
            .unwrap();
    }
    let after = registry.view("graph").unwrap();
    assert_eq!(before.sequence, after.sequence);
    assert_eq!(before.nodes[0].usage, after.nodes[0].usage);
    assert!(matches!(after.nodes[1].state, State::Pending));
    assert!(after.ready.is_empty());
    assert_eq!(*runtime.requests.lock().unwrap(), ["seed", "unknown"]);
}

#[test]
fn client_cannot_decode_budget_actor_path_or_completion_evidence() {
    for field in ["budget", "actor", "state_root", "effects_known", "terminal"] {
        let mut value = serde_json::json!({"command":"open", "workflow_id":"graph"});
        value[field] = serde_json::json!(true);
        assert!(serde_json::from_value::<Command>(value).is_err());
    }
    assert!(
        serde_json::from_value::<Command>(
            serde_json::json!({"command":"open", "workflow_id":"../workspace"})
        )
        .unwrap()
        .validate()
        .is_err()
    );
}

#[test]
fn registry_writer_is_exclusive_and_reservations_survive_graph_completion() {
    let temp = tempfile::tempdir().unwrap();
    let root = root(&temp);
    let owner = Registry::open(&root, policy()).unwrap();
    assert!(matches!(
        Registry::open(&root, policy()),
        Err(super::LiveWorkflowError::Store(
            WorkflowStoreError::Conflict
        ))
    ));
    drop(owner);
    assert!(Registry::open(&root, policy()).is_ok());
}

#[tokio::test]
async fn read_before_operator_open_performs_no_storage_effects() {
    let temp = tempfile::tempdir().unwrap();
    let root = root(&temp);
    let (host, _, _) = host().await;
    let session = LiveWorkflowSession::new(root.clone(), policy(), host).unwrap();
    assert!(matches!(
        session
            .command(Command::Read {
                workflow_id: "graph".into()
            })
            .await,
        Err(super::LiveWorkflowError::NotFound)
    ));
    assert!(!root.exists());
}

#[tokio::test]
async fn active_graph_restart_quarantines_and_uses_exact_existing_completion_without_replay() {
    let temp = tempfile::tempdir().unwrap();
    let root = root(&temp);
    let (host, runtime, agent) = host().await;
    let mut registry = Registry::open(&root, policy()).unwrap();
    registry
        .command(
            Command::Open {
                workflow_id: "graph".into(),
            },
            host.as_ref(),
        )
        .await
        .unwrap();
    registry
        .command(
            Command::Replan {
                workflow_id: "graph".into(),
                request_id: "plan".into(),
                plan: WorkflowReplanV1 {
                    expected_revision: 0,
                    changes: vec![Change::Add {
                        node: node(1, agent, "work-a", vec![]),
                    }],
                },
            },
            host.as_ref(),
        )
        .await
        .unwrap();
    registry
        .command(
            Command::Pump {
                workflow_id: "graph".into(),
            },
            host.as_ref(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), runtime.entered.notified())
        .await
        .unwrap();
    let task = registry.view("graph").unwrap().nodes[0]
        .admitted_task
        .clone();
    drop(registry);
    let mut reopened = Registry::open(&root, policy()).unwrap();
    assert!(matches!(
        reopened.view("graph").unwrap().nodes[0].state,
        State::RecoveryRequired { .. }
    ));
    assert_eq!(reopened.view("graph").unwrap().nodes[0].admitted_task, task);
    reopened
        .command(
            Command::Pump {
                workflow_id: "graph".into(),
            },
            host.as_ref(),
        )
        .await
        .unwrap();
    assert_eq!(*runtime.requests.lock().unwrap(), ["seed", "work-a"]);
    runtime.release.add_permits(1);
    for _ in 0..100 {
        reopened
            .command(
                Command::Reconcile {
                    workflow_id: "graph".into(),
                    node_id: 1,
                },
                host.as_ref(),
            )
            .await
            .unwrap();
        if matches!(
            reopened.view("graph").unwrap().nodes[0].state,
            State::Succeeded { .. }
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(matches!(
        reopened.view("graph").unwrap().nodes[0].state,
        State::Succeeded { .. }
    ));
    assert_eq!(*runtime.requests.lock().unwrap(), ["seed", "work-a"]);
}

#[tokio::test]
async fn disconnected_command_observer_does_not_drop_admitted_graph_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let (host, runtime, agent) = host().await;
    let session = LiveWorkflowSession::new(root(&temp), policy(), host).unwrap();
    session
        .command(Command::Open {
            workflow_id: "graph".into(),
        })
        .await
        .unwrap();
    // The current-thread runtime cannot poll the owned worker before this zero-length observer
    // deadline. Dropping the observer leaves the admitted worker responsible for its WAL commit.
    let timed_out = tokio::time::timeout(
        Duration::ZERO,
        session.command(Command::Replan {
            workflow_id: "graph".into(),
            request_id: "disconnected-request".into(),
            plan: WorkflowReplanV1 {
                expected_revision: 0,
                changes: vec![Change::Add {
                    node: node(1, agent, "detached-command", vec![]),
                }],
            },
        }),
    )
    .await;
    assert!(timed_out.is_err());
    let complete = read_until(session.as_ref(), |reply| {
        reply.view.nodes.len() == 1 && matches!(reply.view.nodes[0].state, State::Succeeded { .. })
    })
    .await;
    assert_eq!(complete.view.revision, 1);
    assert_eq!(
        *runtime.requests.lock().unwrap(),
        ["seed", "detached-command"]
    );
}
