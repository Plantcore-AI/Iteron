use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

fn id(value: u64) -> TaskId {
    TaskId::new(value).unwrap()
}

fn cid(value: u64) -> CommandId {
    CommandId::new(value).unwrap()
}

fn budget(turns: u32) -> TaskBudget {
    TaskBudget {
        max_turns: turns,
        max_tokens: u64::from(turns) * 1_000,
        max_cost_microusd: u64::from(turns) * 10_000,
        max_wall_ms: u64::from(turns) * 1_000,
    }
}

fn config() -> Config {
    Config::new("test-graph", Limits::default(), budget(100)).unwrap()
}

fn spec(value: u64, parent: Option<u64>, dependencies: &[u64], turns: u32) -> TaskSpec {
    TaskSpec {
        id: id(value),
        parent: parent.map(id),
        dependencies: dependencies.iter().copied().map(id).collect(),
        label: format!("task-{value}"),
        budget: budget(turns),
    }
}

fn create(actor: Actor, spec: TaskSpec) -> Command {
    Command::CreateTask { actor, spec }
}

fn start(task: u64) -> Command {
    Command::StartTask {
        actor: Actor::Controller,
        task: id(task),
    }
}

fn success(task: u64) -> Command {
    Command::CompleteTask {
        actor: Actor::Task(id(task)),
        task: id(task),
        completion: Completion::Succeeded,
        result_digest: Some("a".repeat(64)),
        code: None,
        detail: None,
    }
}

fn fail(task: u64) -> Command {
    Command::CompleteTask {
        actor: Actor::Task(id(task)),
        task: id(task),
        completion: Completion::Failed,
        result_digest: None,
        code: Some("worker_failed".into()),
        detail: Some("bounded failure evidence".into()),
    }
}

#[derive(Debug)]
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "core-task-dag-{label}-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exact_command_retry_is_idempotent_but_conflicting_reuse_is_refused() {
    let mut dag = TaskDag::new(config()).unwrap();
    let command = create(Actor::Controller, spec(1, None, &[], 30));
    let first = dag.apply(cid(1), command.clone()).unwrap();
    assert_eq!(first.sequence, 1);
    assert!(!first.replayed);

    let retry = dag.apply(cid(1), command).unwrap();
    assert_eq!(retry.sequence, 1);
    assert!(retry.replayed);
    assert_eq!(dag.sequence(), 1);
    assert!(matches!(dag.task(id(1)).unwrap().state, TaskState::Ready));

    let conflict = dag.apply(cid(1), create(Actor::Controller, spec(2, None, &[], 20)));
    assert!(matches!(conflict, Err(DagError::CommandConflict(1))));
}

#[test]
fn replay_rejects_a_zero_command_id_even_with_valid_hashes() {
    let mut dag = TaskDag::new(config()).unwrap();
    let command = create(Actor::Controller, spec(1, None, &[], 30));
    let command_digest = super::hash::digest_json(&command).unwrap();
    let mut entry = super::reducer::LogEntry {
        version: 1,
        graph_id: dag.config().graph_id.clone(),
        sequence: 1,
        previous_digest: dag.head_digest().to_string(),
        command_id: CommandId(0),
        command_digest,
        command,
        entry_digest: String::new(),
    };
    entry.entry_digest = super::hash::entry_digest(&entry).unwrap();
    assert!(matches!(
        dag.replay(entry),
        Err(DagError::Corrupt(reason)) if reason.contains("command id zero")
    ));
    assert_eq!(dag.sequence(), 0);
    assert!(dag.task(id(1)).is_none());
}

#[test]
fn dependency_failure_cascades_and_join_order_is_deterministic() {
    let mut dag = TaskDag::new(config()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 20)))
        .unwrap();
    dag.apply(cid(2), create(Actor::Controller, spec(2, None, &[1], 20)))
        .unwrap();
    dag.apply(cid(3), create(Actor::Controller, spec(3, None, &[2], 20)))
        .unwrap();
    assert_eq!(dag.ready_tasks(), vec![id(1)]);

    dag.apply(
        cid(4),
        Command::RegisterJoin {
            actor: Actor::Controller,
            join: JoinSpec {
                id: JoinId::new(1).unwrap(),
                owner: None,
                members: vec![id(3), id(1), id(2)],
                policy: JoinPolicy::AllSucceeded,
            },
        },
    )
    .unwrap();
    assert_eq!(
        dag.join_state(JoinId(1)).unwrap(),
        JoinState::Pending {
            remaining: vec![id(1), id(2), id(3)]
        }
    );

    dag.apply(cid(5), start(1)).unwrap();
    dag.apply(cid(6), fail(1)).unwrap();
    assert!(matches!(
        dag.task(id(2)).unwrap().state,
        TaskState::SkippedDependency { dependency } if dependency == id(1)
    ));
    assert!(matches!(
        dag.task(id(3)).unwrap().state,
        TaskState::SkippedDependency { dependency } if dependency == id(2)
    ));
    assert_eq!(
        dag.join_state(JoinId(1)).unwrap(),
        JoinState::Failed {
            members: vec![id(1), id(2), id(3)]
        }
    );
}

#[test]
fn messages_have_exact_provenance_and_durable_ack_state() {
    let mut dag = TaskDag::new(config()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 40)))
        .unwrap();
    dag.apply(cid(2), start(1)).unwrap();
    dag.apply(
        cid(3),
        create(Actor::Task(id(1)), spec(2, Some(1), &[], 20)),
    )
    .unwrap();
    let message = TaskMessage {
        id: MessageId::new(7).unwrap(),
        from: Some(id(1)),
        to: id(2),
        kind: MessageKind::Steering,
        payload: "inspect the failing test first".into(),
        delivery: DeliveryState::Pending,
    };
    dag.apply(
        cid(4),
        Command::SendMessage {
            actor: Actor::Task(id(1)),
            message,
        },
    )
    .unwrap();
    assert_eq!(dag.pending_messages(id(2)).unwrap().len(), 1);

    let forged = TaskMessage {
        id: MessageId(8),
        from: Some(id(1)),
        to: id(2),
        kind: MessageKind::Control,
        payload: "forged".into(),
        delivery: DeliveryState::Pending,
    };
    assert!(matches!(
        dag.apply(
            cid(5),
            Command::SendMessage {
                actor: Actor::Task(id(2)),
                message: forged
            }
        ),
        Err(DagError::Authority(_))
    ));
    dag.apply(cid(6), start(2)).unwrap();
    dag.apply(
        cid(7),
        Command::AcknowledgeMessage {
            actor: Actor::Task(id(2)),
            message: MessageId(7),
        },
    )
    .unwrap();
    assert!(dag.pending_messages(id(2)).unwrap().is_empty());
    assert_eq!(
        dag.message(MessageId(7)).unwrap().delivery,
        DeliveryState::Acknowledged
    );
}

#[test]
fn cancellation_propagates_and_parent_cannot_finish_before_children() {
    let mut dag = TaskDag::new(config()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 80)))
        .unwrap();
    dag.apply(cid(2), start(1)).unwrap();
    dag.apply(
        cid(3),
        create(Actor::Task(id(1)), spec(2, Some(1), &[], 30)),
    )
    .unwrap();
    dag.apply(cid(4), start(2)).unwrap();
    dag.apply(
        cid(5),
        create(Actor::Task(id(2)), spec(3, Some(2), &[], 10)),
    )
    .unwrap();
    dag.apply(
        cid(6),
        Command::RequestCancel {
            actor: Actor::Controller,
            task: id(1),
            reason: "operator stopped the graph".into(),
        },
    )
    .unwrap();
    assert!(matches!(
        dag.task(id(1)).unwrap().state,
        TaskState::Cancelling { .. }
    ));
    assert!(matches!(
        dag.task(id(2)).unwrap().state,
        TaskState::Cancelling { .. }
    ));
    assert!(matches!(
        dag.task(id(3)).unwrap().state,
        TaskState::Cancelled { .. }
    ));

    assert!(matches!(
        dag.apply(
            cid(7),
            Command::CompleteTask {
                actor: Actor::Task(id(1)),
                task: id(1),
                completion: Completion::Cancelled,
                result_digest: None,
                code: None,
                detail: Some("cancel observed".into())
            }
        ),
        Err(DagError::Transition { .. })
    ));
    dag.apply(
        cid(8),
        Command::CompleteTask {
            actor: Actor::Task(id(2)),
            task: id(2),
            completion: Completion::Cancelled,
            result_digest: None,
            code: None,
            detail: Some("operator stopped the graph".into()),
        },
    )
    .unwrap();
    assert!(matches!(
        &dag.task(id(2)).unwrap().state,
        TaskState::Cancelled { reason } if reason == "operator stopped the graph"
    ));
    dag.apply(
        cid(9),
        Command::CompleteTask {
            actor: Actor::Task(id(1)),
            task: id(1),
            completion: Completion::Cancelled,
            result_digest: None,
            code: None,
            detail: Some("operator stopped the graph".into()),
        },
    )
    .unwrap();
}

#[test]
fn a_child_cannot_run_before_its_parent_so_terminal_parents_cannot_orphan_descendants() {
    let mut dag = TaskDag::new(config()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 80)))
        .unwrap();
    dag.apply(cid(2), create(Actor::Controller, spec(2, Some(1), &[], 20)))
        .unwrap();
    assert!(matches!(
        dag.apply(cid(3), start(2)),
        Err(DagError::Transition { .. })
    ));
    dag.apply(cid(4), start(1)).unwrap();
    dag.apply(cid(5), start(2)).unwrap();
    dag.apply(
        cid(6),
        Command::RequestCancel {
            actor: Actor::Controller,
            task: id(1),
            reason: "stop hierarchy".into(),
        },
    )
    .unwrap();
    assert!(matches!(
        dag.task(id(2)).unwrap().state,
        TaskState::Cancelling { .. }
    ));
}

#[test]
fn aggregate_budget_is_reserved_before_children_or_usage_are_admitted() {
    let mut dag = TaskDag::new(config()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 80)))
        .unwrap();
    let root_remaining = dag.remaining_root_budget().unwrap();
    assert_eq!(root_remaining.max_turns, 20);
    assert_eq!(root_remaining.max_tokens, 20_000);
    assert_eq!(root_remaining.max_cost_microusd, 200_000);
    assert_eq!(root_remaining.max_wall_ms, 100_000);
    assert!(matches!(
        dag.apply(cid(2), create(Actor::Controller, spec(2, None, &[], 30))),
        Err(DagError::Budget(_))
    ));
    dag.apply(cid(3), start(1)).unwrap();
    dag.apply(
        cid(4),
        create(Actor::Task(id(1)), spec(3, Some(1), &[], 30)),
    )
    .unwrap();
    dag.apply(
        cid(5),
        Command::ChargeBudget {
            actor: Actor::Controller,
            task: id(1),
            delta: BudgetUsage {
                turns: 50,
                tokens: 50_000,
                cost_microusd: 500_000,
                wall_ms: 1_000,
            },
        },
    )
    .unwrap();
    let remaining = dag.remaining_budget(id(1)).unwrap();
    assert_eq!(remaining.max_turns, 0);
    assert_eq!(remaining.max_tokens, 0);
    assert_eq!(remaining.max_cost_microusd, 0);
    assert_eq!(remaining.max_wall_ms, 79_000);
    assert!(matches!(
        dag.apply(
            cid(6),
            Command::ChargeBudget {
                actor: Actor::Controller,
                task: id(1),
                delta: BudgetUsage {
                    turns: 1,
                    tokens: 0,
                    cost_microusd: 0,
                    wall_ms: 0,
                }
            }
        ),
        Err(DagError::Budget(_))
    ));
}

#[test]
fn store_replays_exact_state_and_repairs_only_a_torn_final_line() {
    let temp = TempDir::new("replay");
    let path = temp.join("dag.jsonl");
    let command = create(Actor::Controller, spec(1, None, &[], 40));
    {
        let mut store = TaskDagStore::open(&path, config()).unwrap();
        store.submit(cid(1), command.clone()).unwrap();
        store.submit(cid(2), start(1)).unwrap();
    }
    let valid_len = fs::metadata(&path).unwrap().len();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(br#"{"record":"command","entry":{"torn":true}"#)
        .unwrap();
    let torn_len = fs::metadata(&path).unwrap().len();
    assert!(torn_len > valid_len);

    let drift = Config::new("wrong-config", Limits::default(), budget(100)).unwrap();
    assert!(matches!(
        TaskDagStore::open(&path, drift),
        Err(DagError::Corrupt(_))
    ));
    assert_eq!(fs::metadata(&path).unwrap().len(), torn_len);

    let mut reopened = TaskDagStore::open(&path, config()).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), valid_len);
    assert!(reopened.recovered_torn_bytes() > 0);
    assert_eq!(reopened.dag().sequence(), 2);
    assert!(matches!(
        reopened.dag().task(id(1)).unwrap().state,
        TaskState::Running
    ));
    let retry = reopened.submit(cid(1), command).unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.sequence, 1);
}

#[test]
fn store_never_rewrites_a_nonempty_file_without_a_durable_genesis() {
    let temp = TempDir::new("partial-genesis");
    let path = temp.join("dag.jsonl");
    let partial = br#"{"record":"genesis","version":1"#;
    fs::write(&path, partial).unwrap();
    assert!(matches!(
        TaskDagStore::open(&path, config()),
        Err(DagError::Corrupt(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), partial);
}

#[test]
fn partial_append_is_unknown_then_poisoned_and_same_id_recovers_after_tail_repair() {
    let temp = TempDir::new("partial-append");
    let path = temp.join("dag.jsonl");
    let command = create(Actor::Controller, spec(1, None, &[], 40));
    let mut store = TaskDagStore::open(&path, config()).unwrap();
    store.inject_next_append_fault(super::store::TestAppendFault::PartialWrite(23));
    assert!(matches!(
        store.submit(cid(1), command.clone()),
        Err(DagError::DurabilityUnknown(_))
    ));
    assert_eq!(store.dag().sequence(), 0);
    assert!(matches!(
        store.submit(cid(2), create(Actor::Controller, spec(2, None, &[], 20))),
        Err(DagError::Poisoned(_))
    ));
    drop(store);

    let mut reopened = TaskDagStore::open(&path, config()).unwrap();
    assert!(reopened.recovered_torn_bytes() > 0);
    assert_eq!(reopened.dag().sequence(), 0);
    let receipt = reopened.submit(cid(1), command).unwrap();
    assert_eq!(receipt.sequence, 1);
    assert!(!receipt.replayed);
}

#[test]
fn full_append_with_sync_failure_replays_instead_of_reexecuting() {
    let temp = TempDir::new("full-append-sync-failure");
    let path = temp.join("dag.jsonl");
    let command = create(Actor::Controller, spec(1, None, &[], 40));
    let mut store = TaskDagStore::open(&path, config()).unwrap();
    store.inject_next_append_fault(super::store::TestAppendFault::AfterFullWriteBeforeSync);
    assert!(matches!(
        store.submit(cid(1), command.clone()),
        Err(DagError::DurabilityUnknown(_))
    ));
    assert_eq!(store.dag().sequence(), 0);
    assert!(matches!(
        store.submit(cid(1), command.clone()),
        Err(DagError::Poisoned(_))
    ));
    drop(store);

    let mut reopened = TaskDagStore::open(&path, config()).unwrap();
    assert_eq!(reopened.dag().sequence(), 1);
    assert!(reopened.dag().task(id(1)).is_some());
    let receipt = reopened.submit(cid(1), command).unwrap();
    assert_eq!(receipt.sequence, 1);
    assert!(receipt.replayed);
}

#[test]
fn corrupt_durable_prefix_with_a_torn_tail_is_never_truncated() {
    let temp = TempDir::new("corrupt-prefix-torn-tail");
    let path = temp.join("dag.jsonl");
    {
        let mut store = TaskDagStore::open(&path, config()).unwrap();
        store
            .submit(cid(1), create(Actor::Controller, spec(1, None, &[], 40)))
            .unwrap();
    }
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.replacen("task-1", "task-x", 1)).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(br#"{"record":"command","torn":true}"#)
        .unwrap();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        TaskDagStore::open(&path, config()),
        Err(DagError::Corrupt(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn fresh_store_requires_preprovisioned_parent_and_parent_sync_success() {
    let temp = TempDir::new("namespace-sync");
    let missing_parent_path = temp.join("missing").join("dag.jsonl");
    assert!(matches!(
        TaskDagStore::open(&missing_parent_path, config()),
        Err(DagError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(!missing_parent_path.exists());

    let path = temp.join("dag.jsonl");
    assert!(matches!(
        TaskDagStore::open_with_parent_sync_failure(&path, config()),
        Err(DagError::DurabilityUnknown(_))
    ));
    let reopened = TaskDagStore::open(&path, config()).unwrap();
    assert_eq!(reopened.dag().sequence(), 0);
}

#[test]
fn store_refuses_config_drift_hash_tampering_and_a_second_writer() {
    let temp = TempDir::new("corrupt");
    let path = temp.join("dag.jsonl");
    let mut first = TaskDagStore::open(&path, config()).unwrap();
    assert!(matches!(
        TaskDagStore::open(&path, config()),
        Err(DagError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    first
        .submit(cid(1), create(Actor::Controller, spec(1, None, &[], 30)))
        .unwrap();
    drop(first);

    let drift = Config::new("different", Limits::default(), budget(100)).unwrap();
    assert!(matches!(
        TaskDagStore::open(&path, drift),
        Err(DagError::Corrupt(_))
    ));

    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("task-1"));
    fs::write(&path, text.replacen("task-1", "task-x", 1)).unwrap();
    assert!(matches!(
        TaskDagStore::open(&path, config()),
        Err(DagError::Corrupt(_))
    ));
}

#[test]
fn hard_limits_and_ancestor_dependency_deadlocks_are_refused() {
    let limits = Limits {
        max_events: 2,
        ..Limits::default()
    };
    let mut dag = TaskDag::new(Config::new("caps", limits, budget(100)).unwrap()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 80)))
        .unwrap();
    dag.apply(cid(2), create(Actor::Controller, spec(2, Some(1), &[], 20)))
        .unwrap();
    assert!(matches!(
        dag.apply(cid(3), start(1)),
        Err(DagError::EventLimit)
    ));

    let mut deadlock = TaskDag::new(config()).unwrap();
    deadlock
        .apply(cid(1), create(Actor::Controller, spec(1, None, &[], 80)))
        .unwrap();
    assert!(matches!(
        deadlock.apply(
            cid(2),
            create(Actor::Controller, spec(2, Some(1), &[1], 20))
        ),
        Err(DagError::Invalid(_))
    ));
}

#[test]
fn dependency_and_parent_wait_edges_cannot_form_an_admission_cycle() {
    let mut dag = TaskDag::new(config()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 60)))
        .unwrap();
    dag.apply(cid(2), create(Actor::Controller, spec(2, None, &[1], 30)))
        .unwrap();
    dag.apply(cid(3), start(1)).unwrap();

    let sequence = dag.sequence();
    let remaining = dag.remaining_budget(id(1)).unwrap();
    let rejected = dag.apply(
        cid(4),
        create(Actor::Task(id(1)), spec(3, Some(1), &[2], 10)),
    );
    assert!(matches!(rejected, Err(DagError::Invalid(_))));
    assert_eq!(dag.sequence(), sequence);
    assert_eq!(dag.remaining_budget(id(1)).unwrap(), remaining);
    assert!(dag.task(id(3)).is_none());
}

#[test]
fn cancelling_tasks_only_acknowledge_the_original_cause() {
    let mut dag = TaskDag::new(config()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 60)))
        .unwrap();
    dag.apply(cid(2), create(Actor::Controller, spec(2, None, &[1], 20)))
        .unwrap();
    dag.apply(cid(3), start(1)).unwrap();
    dag.apply(
        cid(4),
        Command::RequestCancel {
            actor: Actor::Controller,
            task: id(1),
            reason: "operator cancellation cause".into(),
        },
    )
    .unwrap();

    assert!(matches!(
        dag.apply(cid(5), success(1)),
        Err(DagError::Transition { .. })
    ));
    assert!(matches!(
        dag.apply(cid(6), fail(1)),
        Err(DagError::Transition { .. })
    ));
    assert!(matches!(
        dag.apply(
            cid(7),
            Command::CompleteTask {
                actor: Actor::Task(id(1)),
                task: id(1),
                completion: Completion::Cancelled,
                result_digest: None,
                code: None,
                detail: Some("worker-provided replacement".into()),
            }
        ),
        Err(DagError::Transition { .. })
    ));
    assert_eq!(dag.sequence(), 4);

    dag.apply(
        cid(8),
        Command::CompleteTask {
            actor: Actor::Task(id(1)),
            task: id(1),
            completion: Completion::Cancelled,
            result_digest: None,
            code: None,
            detail: Some("operator cancellation cause".into()),
        },
    )
    .unwrap();
    assert!(matches!(
        &dag.task(id(1)).unwrap().state,
        TaskState::Cancelled { reason } if reason == "operator cancellation cause"
    ));
    assert!(matches!(
        dag.task(id(2)).unwrap().state,
        TaskState::SkippedDependency { dependency } if dependency == id(1)
    ));
}

#[test]
fn parent_links_count_as_edges_and_unknown_wire_fields_fail_closed() {
    let limits = Limits {
        max_edges: 1,
        ..Limits::default()
    };
    let mut dag = TaskDag::new(Config::new("edge-cap", limits, budget(100)).unwrap()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 80)))
        .unwrap();
    dag.apply(cid(2), create(Actor::Controller, spec(2, Some(1), &[], 40)))
        .unwrap();
    assert!(matches!(
        dag.apply(cid(3), create(Actor::Controller, spec(3, Some(2), &[], 10))),
        Err(DagError::Capacity { .. })
    ));

    let mut wire = serde_json::to_value(start(1)).unwrap();
    wire.as_object_mut()
        .unwrap()
        .insert("surprise".into(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<Command>(wire).is_err());
}

#[test]
fn task_actors_must_be_running_and_child_wall_budgets_fit_remaining_time() {
    let mut dag = TaskDag::new(config()).unwrap();
    let mut root = spec(1, None, &[], 80);
    root.budget.max_wall_ms = 2_000;
    dag.apply(cid(1), create(Actor::Controller, root)).unwrap();
    assert!(matches!(
        dag.apply(
            cid(2),
            create(Actor::Task(id(1)), spec(2, Some(1), &[], 10))
        ),
        Err(DagError::Transition { .. })
    ));

    dag.apply(cid(3), start(1)).unwrap();
    dag.apply(
        cid(4),
        Command::ChargeBudget {
            actor: Actor::Controller,
            task: id(1),
            delta: BudgetUsage {
                wall_ms: 1_500,
                ..BudgetUsage::default()
            },
        },
    )
    .unwrap();
    let mut child = spec(2, Some(1), &[], 1);
    child.budget.max_wall_ms = 1_000;
    assert!(matches!(
        dag.apply(cid(5), create(Actor::Task(id(1)), child)),
        Err(DagError::Budget(_))
    ));
}

#[test]
fn variable_width_commands_are_bounded_before_stateful_validation_and_digesting() {
    let mut dag = TaskDag::new(config()).unwrap();
    let mut oversized = spec(1, None, &[], 1);
    oversized.dependencies = vec![id(9); dag.config().limits.max_edges + 1];
    assert!(matches!(
        dag.apply(cid(1), create(Actor::Controller, oversized)),
        Err(DagError::Capacity { kind: "edge" })
    ));
    assert_eq!(dag.sequence(), 0);

    let oversized_message = TaskMessage {
        id: MessageId(1),
        from: None,
        to: id(99),
        kind: MessageKind::Instruction,
        payload: "x".repeat(super::types::MAX_MESSAGE_BYTES + 1),
        delivery: DeliveryState::Pending,
    };
    assert!(matches!(
        dag.apply(
            cid(2),
            Command::SendMessage {
                actor: Actor::Controller,
                message: oversized_message,
            }
        ),
        Err(DagError::Invalid(_))
    ));
    assert_eq!(dag.sequence(), 0);
}

#[cfg(unix)]
#[test]
fn durable_store_refuses_a_symlink_target() {
    let temp = TempDir::new("symlink");
    let real = temp.join("real.jsonl");
    fs::write(&real, b"").unwrap();
    let link = temp.join("linked.jsonl");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(matches!(
        TaskDagStore::open(link, config()),
        Err(DagError::Io(_))
    ));
}

#[cfg(windows)]
#[test]
fn durable_store_refuses_a_windows_reparse_target() {
    let temp = TempDir::new("windows-reparse");
    let real = temp.join("real.jsonl");
    fs::write(&real, b"").unwrap();
    let link = temp.join("linked.jsonl");
    if std::os::windows::fs::symlink_file(&real, &link).is_err() {
        // Creating a symlink can require Developer Mode or a privilege on older Windows hosts.
        return;
    }
    assert!(matches!(
        TaskDagStore::open(link, config()),
        Err(DagError::Io(_))
    ));
}

#[test]
fn a_successful_dependency_releases_ready_tasks_in_task_id_order() {
    let mut dag = TaskDag::new(config()).unwrap();
    dag.apply(cid(1), create(Actor::Controller, spec(1, None, &[], 20)))
        .unwrap();
    dag.apply(cid(2), create(Actor::Controller, spec(3, None, &[1], 20)))
        .unwrap();
    dag.apply(cid(3), create(Actor::Controller, spec(2, None, &[1], 20)))
        .unwrap();
    dag.apply(cid(4), start(1)).unwrap();
    dag.apply(cid(5), success(1)).unwrap();
    assert_eq!(dag.ready_tasks(), vec![id(2), id(3)]);
}
