#[tokio::test]
async fn ordinary_edit_finishes_without_an_implicit_git_snapshot() {
    let ws = temp_ws("ordinary-edit-no-checkpoint");
    init_git_workspace(&ws);
    std::fs::write(ws.join("f.txt"), "a").unwrap();
    let runs = ws.join(".iteron/runs");
    let run = iteron_protocol::RunId("ordinary-edit-no-checkpoint".into());
    let rollout = Rollout::open(&runs, &run, iteron_protocol::TenantId::default()).unwrap();
    let mut agent = Agent::new(
        std::sync::Arc::new(ScriptedEdit::default()),
        Registry::coding_agent_for_tests(&ws).unwrap(),
        rollout,
        "m".into(),
        "sys".into(),
        Budget::default(),
    );
    agent.workspace = ws.clone();
    agent.bypass_permissions = true;
    assert_eq!(agent.run("change a to b").await.unwrap(), Outcome::Done);
    assert_eq!(std::fs::read_to_string(ws.join("f.txt")).unwrap(), "b");
    let events = iteron_record::replay(&runs.join(format!("{run}.jsonl"))).unwrap();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, EventKind::Checkpoint { .. }))
    );
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        EventKind::Done { outcome } if outcome == "Done"
    )));
    drop(agent);
    let _ = std::fs::remove_dir_all(ws);
}
