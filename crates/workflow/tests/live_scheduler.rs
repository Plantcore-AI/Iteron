use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use iteron_workflow::live_scheduler::{
    AgentTurnLeaseV1, ScheduledTaskV1, WorkflowCompletionV1, WorkflowConfigV1,
    WorkflowControllerPort, WorkflowDispatchError, WorkflowNodeStateV1 as State, WorkflowNodeV1,
    WorkflowPlanChangeV1 as Change, WorkflowPlanJournal, WorkflowReplanV1, WorkflowScheduler,
    WorkflowSchedulerError as Error, WorkflowSchedulerSnapshotV1, WorkflowStoreError,
};
use iteron_workflow::task_dag::{BudgetUsage, TaskBudget};

#[derive(Clone, Default)]
struct MemoryJournal(Arc<Mutex<MemoryState>>);

#[derive(Default)]
struct MemoryState {
    snapshot: Option<WorkflowSchedulerSnapshotV1>,
    fail_next_after_publish: bool,
    fail_next_before_publish: bool,
}

impl WorkflowPlanJournal for MemoryJournal {
    fn load(&mut self) -> Result<Option<WorkflowSchedulerSnapshotV1>, WorkflowStoreError> {
        Ok(self.0.lock().unwrap().snapshot.clone())
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &WorkflowSchedulerSnapshotV1,
    ) -> Result<(), WorkflowStoreError> {
        let mut state = self.0.lock().unwrap();
        if state.snapshot.as_ref().map(|s| s.sequence()) != expected {
            return Err(WorkflowStoreError::Conflict);
        }
        if state.fail_next_before_publish {
            state.fail_next_before_publish = false;
            return Err(WorkflowStoreError::Unavailable);
        }
        state.snapshot = Some(next.clone());
        if state.fail_next_after_publish {
            state.fail_next_after_publish = false;
            return Err(WorkflowStoreError::OutcomeUnknown);
        }
        Ok(())
    }
}

#[derive(Default)]
struct Controller {
    dispatched: Mutex<Vec<ScheduledTaskV1>>,
    interrupted: Mutex<Vec<AgentTurnLeaseV1>>,
    fail_dispatch: Mutex<Option<WorkflowDispatchError>>,
}

#[async_trait]
impl WorkflowControllerPort for Controller {
    async fn dispatch(
        &self,
        task: ScheduledTaskV1,
    ) -> Result<AgentTurnLeaseV1, WorkflowDispatchError> {
        let lease = AgentTurnLeaseV1 {
            agent_id: task.assigned_agent,
            incarnation: 1,
            turn: task.attempt,
        };
        self.dispatched.lock().unwrap().push(task);
        match self.fail_dispatch.lock().unwrap().take() {
            Some(error) => Err(error),
            None => Ok(lease),
        }
    }
    async fn interrupt(&self, lease: AgentTurnLeaseV1) -> Result<(), WorkflowDispatchError> {
        self.interrupted.lock().unwrap().push(lease);
        Ok(())
    }
}

fn config() -> WorkflowConfigV1 {
    WorkflowConfigV1 {
        workflow_id: "live-test".into(),
        budget: TaskBudget {
            max_turns: 20,
            max_tokens: 20_000,
            max_cost_microusd: 20_000,
            max_wall_ms: 20_000,
        },
        max_nodes: 20,
        max_edges: 40,
        max_concurrency: 3,
        started_at_unix_ms: 100,
        deadline_unix_ms: 20_100,
    }
}

fn node(id: u64, dependencies: &[u64]) -> WorkflowNodeV1 {
    WorkflowNodeV1 {
        id,
        label: format!("node-{id}"),
        task: format!("inspect node {id}"),
        dependencies: dependencies.into(),
        assigned_agent: id,
        input_digest: format!("{id:064x}"),
        budget: TaskBudget {
            max_turns: 1,
            max_tokens: 1_000,
            max_cost_microusd: 1_000,
            max_wall_ms: 1_000,
        },
    }
}

fn plan(expected_revision: u64, changes: Vec<Change>) -> WorkflowReplanV1 {
    WorkflowReplanV1 {
        expected_revision,
        changes,
    }
}

fn usage() -> BudgetUsage {
    BudgetUsage {
        turns: 1,
        tokens: 20,
        cost_microusd: 5,
        wall_ms: 100,
    }
}

fn succeeded(scheduler: &mut WorkflowScheduler<MemoryJournal>, node: u64) {
    let snapshot = scheduler.snapshot().unwrap();
    let record = snapshot.node(node).unwrap();
    scheduler
        .settle(
            node,
            record.state.attempt().unwrap(),
            record.state.lease().unwrap(),
            WorkflowCompletionV1::Succeeded {
                result_digest: format!("{node:064x}"),
            },
            usage(),
            true,
        )
        .unwrap();
}

#[tokio::test]
async fn running_result_replans_future_graph_without_reexecuting_completed_work() {
    let journal = MemoryJournal::default();
    let mut scheduler = WorkflowScheduler::open(journal, config()).unwrap();
    let controller = Controller::default();
    scheduler
        .replan(
            "initial",
            plan(
                0,
                vec![
                    Change::Add { node: node(1, &[]) },
                    Change::Add {
                        node: node(2, &[1]),
                    },
                ],
            ),
        )
        .unwrap();
    assert_eq!(scheduler.ready_nodes(100).unwrap(), [1]);
    scheduler.dispatch(1, &controller, 100).await.unwrap();
    // A genuine live edit while A is active adds future sibling C and changes B's assignment.
    let mut b = node(2, &[1]);
    b.assigned_agent = 22;
    scheduler
        .replan(
            "live-edit",
            plan(
                1,
                vec![
                    Change::Add {
                        node: node(3, &[1]),
                    },
                    Change::ReplacePending { node: b },
                ],
            ),
        )
        .unwrap();
    assert!(scheduler.ready_nodes(101).unwrap().is_empty());
    succeeded(&mut scheduler, 1);
    assert_eq!(scheduler.ready_nodes(201).unwrap(), [2, 3]);
    scheduler.dispatch(2, &controller, 201).await.unwrap();
    scheduler.dispatch(3, &controller, 201).await.unwrap();
    succeeded(&mut scheduler, 2);
    succeeded(&mut scheduler, 3);
    scheduler
        .replan(
            "result-replan",
            plan(
                2,
                vec![Change::Add {
                    node: node(4, &[2, 3]),
                }],
            ),
        )
        .unwrap();
    assert_eq!(scheduler.ready_nodes(301).unwrap(), [4]);
    scheduler.dispatch(4, &controller, 301).await.unwrap();
    succeeded(&mut scheduler, 4);
    assert!(scheduler.ready_nodes(401).unwrap().is_empty());
    let calls = controller.dispatched.lock().unwrap();
    assert_eq!(
        calls.iter().map(|c| c.node_id).collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert_eq!(calls[1].assigned_agent, 22);
    assert_eq!(scheduler.snapshot().unwrap().revision(), 3);
    assert_eq!(scheduler.snapshot().unwrap().reserved_budget().turns, 4);
}

#[tokio::test]
async fn cas_cycle_active_mutation_and_finished_retry_are_atomic_refusals() {
    let mut scheduler = WorkflowScheduler::open(MemoryJournal::default(), config()).unwrap();
    let initial = plan(
        0,
        vec![
            Change::Add { node: node(1, &[]) },
            Change::Add {
                node: node(2, &[1]),
            },
        ],
    );
    let receipt = scheduler.replan("initial", initial.clone()).unwrap();
    assert!(!receipt.replayed);
    assert!(scheduler.replan("initial", initial).unwrap().replayed);
    let before = scheduler.snapshot().unwrap();
    assert!(matches!(
        scheduler.replan(
            "concurrent",
            plan(0, vec![Change::Add { node: node(3, &[]) }])
        ),
        Err(Error::RevisionConflict { .. })
    ));
    assert!(matches!(
        scheduler.replan(
            "cycle",
            plan(
                1,
                vec![Change::ReplacePending {
                    node: node(1, &[2])
                }]
            )
        ),
        Err(Error::Invalid("dependency cycle"))
    ));
    assert_eq!(scheduler.snapshot().unwrap(), before);
    let controller = Controller::default();
    scheduler.dispatch(1, &controller, 100).await.unwrap();
    assert!(matches!(
        scheduler.replan(
            "active",
            plan(1, vec![Change::RemovePending { node_id: 1 }])
        ),
        Err(Error::Transition(_))
    ));
    succeeded(&mut scheduler, 1);
    assert!(matches!(
        scheduler.replan(
            "rerun-completed",
            plan(1, vec![Change::Retry { node: node(1, &[]) }])
        ),
        Err(Error::Transition(_))
    ));
    assert_eq!(scheduler.ready_nodes(200).unwrap(), [2]);
    assert_eq!(controller.dispatched.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn cancel_ack_requires_actual_settlement_then_explicit_retry_rejects_old_epoch() {
    let mut scheduler = WorkflowScheduler::open(MemoryJournal::default(), config()).unwrap();
    scheduler
        .replan("initial", plan(0, vec![Change::Add { node: node(1, &[]) }]))
        .unwrap();
    let controller = Controller::default();
    scheduler.dispatch(1, &controller, 100).await.unwrap();
    let old = scheduler
        .snapshot()
        .unwrap()
        .node(1)
        .unwrap()
        .state
        .lease()
        .unwrap();
    assert!(matches!(
        scheduler.interrupt(1, &controller).await.unwrap(),
        State::Cancelling { .. }
    ));
    assert!(matches!(
        scheduler.replan(
            "too-early",
            plan(1, vec![Change::Retry { node: node(1, &[]) }])
        ),
        Err(Error::Transition(_))
    ));
    scheduler
        .settle(
            1,
            1,
            old,
            WorkflowCompletionV1::Cancelled {
                detail: "supervisor reaped".into(),
            },
            usage(),
            true,
        )
        .unwrap();
    let mut reassigned = node(1, &[]);
    reassigned.assigned_agent = 9;
    scheduler
        .replan(
            "reassign",
            plan(1, vec![Change::Retry { node: reassigned }]),
        )
        .unwrap();
    scheduler.dispatch(1, &controller, 250).await.unwrap();
    assert!(matches!(
        scheduler.settle(
            1,
            1,
            old,
            WorkflowCompletionV1::Succeeded {
                result_digest: "1".repeat(64)
            },
            usage(),
            true
        ),
        Err(Error::StaleLease)
    ));
    let current = scheduler.snapshot().unwrap();
    let record = current.node(1).unwrap();
    assert_eq!(record.state.attempt(), Some(2));
    assert_eq!(record.state.lease().unwrap().agent_id, 9);
    assert_eq!(controller.interrupted.lock().unwrap().as_slice(), [old]);
}

#[tokio::test]
async fn restart_quarantines_active_attempt_and_retains_budget_and_completed_input() {
    let journal = MemoryJournal::default();
    let mut scheduler = WorkflowScheduler::open(journal.clone(), config()).unwrap();
    scheduler
        .replan(
            "initial",
            plan(
                0,
                vec![
                    Change::Add { node: node(1, &[]) },
                    Change::Add { node: node(2, &[]) },
                ],
            ),
        )
        .unwrap();
    let controller = Controller::default();
    scheduler.dispatch(1, &controller, 100).await.unwrap();
    succeeded(&mut scheduler, 1);
    scheduler.dispatch(2, &controller, 200).await.unwrap();
    let lease = scheduler
        .snapshot()
        .unwrap()
        .node(2)
        .unwrap()
        .state
        .lease()
        .unwrap();
    let reserved = scheduler.snapshot().unwrap().reserved_budget();
    drop(scheduler);
    let mut recovered = WorkflowScheduler::open(journal.clone(), config()).unwrap();
    let snapshot = recovered.snapshot().unwrap();
    assert!(matches!(
        snapshot.node(1).unwrap().state,
        State::Succeeded { .. }
    ));
    assert!(matches!(
        snapshot.node(2).unwrap().state,
        State::RecoveryRequired { .. }
    ));
    assert_eq!(snapshot.reserved_budget(), reserved);
    assert!(recovered.ready_nodes(300).unwrap().is_empty());
    assert!(matches!(
        recovered
            .reconcile_stopped(
                2,
                1,
                WorkflowCompletionV1::Cancelled {
                    detail: "effects unknown".into()
                },
                usage(),
                false
            )
            .unwrap(),
        State::RecoveryRequired { .. }
    ));
    assert_eq!(
        recovered.snapshot().unwrap().node(2).unwrap().usage,
        usage()
    );
    // Cumulative reconciliation receipts must not double-charge usage already recorded.
    recovered
        .settle(
            2,
            1,
            lease,
            WorkflowCompletionV1::Cancelled {
                detail: "orphan was reaped".into(),
            },
            usage(),
            true,
        )
        .unwrap();
    assert_eq!(
        recovered.snapshot().unwrap().node(2).unwrap().usage,
        usage()
    );
    assert_eq!(controller.dispatched.lock().unwrap().len(), 2);
    assert!(recovered.ready_nodes(400).unwrap().is_empty());
}

#[tokio::test]
async fn ambiguous_dispatch_or_durable_publication_never_claims_a_safe_retry() {
    let journal = MemoryJournal::default();
    let mut scheduler = WorkflowScheduler::open(journal.clone(), config()).unwrap();
    scheduler
        .replan("initial", plan(0, vec![Change::Add { node: node(1, &[]) }]))
        .unwrap();
    let controller = Controller::default();
    *controller.fail_dispatch.lock().unwrap() = Some(WorkflowDispatchError::OutcomeUnknown(
        "lost after dispatch".into(),
    ));
    assert!(matches!(
        scheduler.dispatch(1, &controller, 100).await.unwrap(),
        State::RecoveryRequired { lease: None, .. }
    ));
    assert!(scheduler.ready_nodes(200).unwrap().is_empty());
    assert!(matches!(
        scheduler.replan(
            "retry-unknown",
            plan(1, vec![Change::Retry { node: node(1, &[]) }])
        ),
        Err(Error::Transition(_))
    ));
    scheduler
        .reconcile_stopped(
            1,
            1,
            WorkflowCompletionV1::Cancelled {
                detail: "controller confirms no live process".into(),
            },
            BudgetUsage::default(),
            true,
        )
        .unwrap();
    journal.0.lock().unwrap().fail_next_after_publish = true;
    let retry = plan(1, vec![Change::Retry { node: node(1, &[]) }]);
    assert!(matches!(
        scheduler.replan("safe-retry", retry.clone()),
        Err(Error::Store(WorkflowStoreError::OutcomeUnknown))
    ));
    assert!(matches!(scheduler.snapshot(), Err(Error::Poisoned)));
    let mut recovered = WorkflowScheduler::open(journal, config()).unwrap();
    assert!(recovered.replan("safe-retry", retry).unwrap().replayed);
    assert_eq!(controller.dispatched.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn host_bounds_deadlines_same_agent_concurrency_and_attempt_budget() {
    let mut config = config();
    config.budget.max_turns = 1;
    let mut scheduler = WorkflowScheduler::open(MemoryJournal::default(), config).unwrap();
    let mut sibling = node(2, &[]);
    sibling.assigned_agent = 1;
    scheduler
        .replan(
            "initial",
            plan(
                0,
                vec![
                    Change::Add { node: node(1, &[]) },
                    Change::Add { node: sibling },
                ],
            ),
        )
        .unwrap();
    assert_eq!(scheduler.ready_nodes(100).unwrap(), [1]);
    let controller = Controller::default();
    scheduler.dispatch(1, &controller, 100).await.unwrap();
    assert!(scheduler.ready_nodes(101).unwrap().is_empty());
    assert_eq!(scheduler.expired_nodes(1_100).unwrap(), [1]);
    assert!(scheduler.expired_nodes(1_099).unwrap().is_empty());
    succeeded(&mut scheduler, 1);
    assert!(scheduler.ready_nodes(200).unwrap().is_empty());
    assert!(scheduler.ready_nodes(20_100).unwrap().is_empty());
    assert!(matches!(scheduler.ready_nodes(99), Err(Error::Invalid(_))));
    assert!(matches!(
        scheduler.dispatch(2, &controller, 200).await,
        Err(Error::Transition(_))
    ));
    assert_eq!(controller.dispatched.lock().unwrap().len(), 1);
}

#[test]
fn graph_removal_preserves_tombstones_and_atomic_reference_integrity() {
    let journal = MemoryJournal::default();
    let mut scheduler = WorkflowScheduler::open(journal.clone(), config()).unwrap();
    scheduler
        .replan(
            "initial",
            plan(
                0,
                vec![
                    Change::Add { node: node(1, &[]) },
                    Change::Add {
                        node: node(2, &[1]),
                    },
                ],
            ),
        )
        .unwrap();
    let before = scheduler.snapshot().unwrap();
    assert!(matches!(
        scheduler.replan(
            "dangling",
            plan(1, vec![Change::RemovePending { node_id: 1 }])
        ),
        Err(Error::Invalid(_))
    ));
    assert_eq!(scheduler.snapshot().unwrap(), before);
    journal.0.lock().unwrap().fail_next_before_publish = true;
    assert!(matches!(
        scheduler.replan(
            "prune",
            plan(
                1,
                vec![
                    Change::RemovePending { node_id: 1 },
                    Change::ReplacePending { node: node(2, &[]) }
                ]
            )
        ),
        Err(Error::Store(WorkflowStoreError::Unavailable))
    ));
    assert_eq!(scheduler.snapshot().unwrap(), before);
    scheduler
        .replan(
            "prune",
            plan(
                1,
                vec![
                    Change::RemovePending { node_id: 1 },
                    Change::ReplacePending { node: node(2, &[]) },
                ],
            ),
        )
        .unwrap();
    assert_eq!(scheduler.ready_nodes(100).unwrap(), [2]);
    assert!(matches!(
        scheduler.replan("reuse", plan(2, vec![Change::Add { node: node(1, &[]) }])),
        Err(Error::Transition(_))
    ));
}
