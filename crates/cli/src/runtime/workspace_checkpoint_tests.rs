//! A real Git snapshot must not replace rollback state across a refused record publication.
use super::{DurableAppendFault, EventKind, TurnId, gate_integration_tests};
use std::process::{Command, Stdio};

#[test]
fn actual_snapshot_keeps_last_confirmed_owner_state_after_publication_refusal() {
    let workspace = gate_integration_tests::temp_ws("checkpoint-owner-refusal");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&workspace)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(workspace.join("f.txt"), "first physical snapshot\n").unwrap();
    let mut agent = gate_integration_tests::agent_for(&workspace);
    gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent
        .record_genesis_with_tunables(workspace.display().to_string(), 1, String::new(), None)
        .unwrap();
    agent.checkpoint_at_turn_end(TurnId(0), true).unwrap();
    let first = agent.workspace_checkpoints.latest().unwrap().clone();
    let record = iteron_record::replay(agent.rollout.path()).unwrap();
    assert!(record.iter().any(|event| matches!(&event.kind,
        EventKind::Checkpoint { at, tree_ref } if event.seq == first.at && at == &first.at && tree_ref == &first.tree_ref)));

    std::fs::write(workspace.join("f.txt"), "second physical snapshot\n").unwrap();
    agent.fail_next_durable_append = Some(DurableAppendFault::Checkpoint);
    assert!(agent.checkpoint_at_turn_end(TurnId(1), true).is_err());
    assert!(agent.record_failed);
    let retained = agent.workspace_checkpoints.latest().unwrap();
    assert_eq!(retained.at, first.at);
    assert_eq!(retained.tree_ref, first.tree_ref);
    assert!(agent.workspace_checkpoints.interval_elapsed(TurnId(1), 1));
    let record = iteron_record::replay(agent.rollout.path()).unwrap();
    assert_eq!(
        record
            .iter()
            .filter(|event| matches!(event.kind, EventKind::Checkpoint { .. }))
            .count(),
        1
    );
    assert!(record.iter().any(|event| event.turn == TurnId(1)
        && matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "checkpoint")));
    drop(agent);
    let _ = std::fs::remove_dir_all(workspace);
}
