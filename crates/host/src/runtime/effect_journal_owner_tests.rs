use super::{EffectJournalOwner, UnknownCause};
use iteron_kernel::effects;
use iteron_obs::Ledger;
use iteron_protocol::product_contract::TerminalEffectStateV1;
use iteron_protocol::{Capability, RunId, TenantId, ToolResult, ToolUse, Trust, TurnId};
use iteron_record::Rollout;
use std::path::PathBuf;

fn workspace(name: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "iteron-effect-owner-{name}-{}-{next}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn call() -> ToolUse {
    ToolUse {
        id: "actual-tool".into(),
        name: "write_file".into(),
        input: serde_json::json!({"path":"result.txt","content":"done"}),
    }
}

#[test]
fn actual_terminal_restart_keeps_identity_singular() {
    let workspace = workspace("known-restart");
    let run = RunId("actual".into());
    let mut rollout = Rollout::open(&workspace, &run, TenantId::default()).unwrap();
    let mut owner = EffectJournalOwner::default();
    owner
        .guard_recovery(&mut rollout, &mut Ledger::default())
        .unwrap();
    assert!(owner.parent_settlement_known());
    let call = call();
    let ticket = owner
        .open_tool(
            &mut rollout,
            &workspace,
            TurnId(1),
            0,
            &call,
            Capability::ReversibleLocal,
        )
        .unwrap();
    assert!(!owner.parent_settlement_known());
    owner
        .settle_tool(
            &mut rollout,
            ticket,
            &call.name,
            &ToolResult {
                tool_use_id: call.id.clone(),
                content: "done".into(),
                is_error: false,
                trust: Trust::Workspace,
                latency_ms: 1,
            },
        )
        .unwrap();
    assert!(owner.parent_settlement_known());
    drop(rollout);
    let mut restarted = Rollout::open_existing(&workspace, &run, TenantId::default()).unwrap();
    let mut recovered = EffectJournalOwner::default();
    recovered
        .guard_recovery(&mut restarted, &mut Ledger::default())
        .unwrap();
    let before = iteron_record::replay(restarted.path()).unwrap().len();
    assert!(matches!(
        recovered.open_tool(
            &mut restarted,
            &workspace,
            TurnId(1),
            0,
            &call,
            Capability::ReversibleLocal
        ),
        Err(effects::BrokerError::Admission(_))
    ));
    assert_eq!(
        iteron_record::replay(restarted.path()).unwrap().len(),
        before
    );
    drop(restarted);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn explicit_cancel_does_not_hide_unknown_from_real_restart() {
    let workspace = workspace("cancel-restart");
    let run = RunId("actual".into());
    let mut rollout = Rollout::open(&workspace, &run, TenantId::default()).unwrap();
    let mut owner = EffectJournalOwner::default();
    owner
        .guard_recovery(&mut rollout, &mut Ledger::default())
        .unwrap();
    let ticket = owner
        .open_tool(
            &mut rollout,
            &workspace,
            TurnId(1),
            0,
            &call(),
            Capability::ReversibleLocal,
        )
        .unwrap();
    owner
        .settle(
            &mut rollout,
            ticket,
            effects::Settlement::Unknown("operator interrupted physical writer".into()),
            UnknownCause::OperatorCancelled,
        )
        .unwrap();
    owner
        .guard_recovery(&mut rollout, &mut Ledger::default())
        .unwrap();
    assert_eq!(owner.unresolved_count(), 0);
    assert!(!owner.parent_settlement_known());
    drop(rollout);
    let mut restarted = Rollout::open_existing(&workspace, &run, TenantId::default()).unwrap();
    let mut recovered = EffectJournalOwner::default();
    for _ in 0..2 {
        assert!(matches!(
            recovered.guard_recovery(&mut restarted, &mut Ledger::default()),
            Err(super::KernelError::UnknownEffects { count: 1 })
        ));
    }
    assert_eq!(
        iteron_record::replay(restarted.path())
            .unwrap()
            .iter()
            .filter(|event| matches!(event.kind, iteron_protocol::EventKind::EffectUnknown { .. }))
            .count(),
        1
    );
    drop(restarted);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn live_terminal_scope_tracks_receipts_and_product_boundaries() {
    let workspace = workspace("terminal-scope");
    let mut rollout =
        Rollout::open(&workspace, &RunId("actual".into()), TenantId::default()).unwrap();
    let mut owner = EffectJournalOwner::default();
    owner
        .guard_recovery(&mut rollout, &mut Ledger::default())
        .unwrap();
    let first = rollout.next_sequence();
    owner.begin_terminal_scope(&rollout, first);
    assert_eq!(
        owner.terminal_state(&rollout, first),
        Some(TerminalEffectStateV1::NotDispatched)
    );
    let call = call();
    let ticket = owner
        .open_tool(
            &mut rollout,
            &workspace,
            TurnId(1),
            0,
            &call,
            Capability::ReversibleLocal,
        )
        .unwrap();
    assert_eq!(
        owner.terminal_state(&rollout, first),
        Some(TerminalEffectStateV1::Unknown)
    );
    owner
        .settle_tool(
            &mut rollout,
            ticket,
            &call.name,
            &ToolResult {
                tool_use_id: call.id.clone(),
                content: "done".into(),
                is_error: false,
                trust: Trust::Workspace,
                latency_ms: 1,
            },
        )
        .unwrap();
    assert_eq!(
        owner.terminal_state(&rollout, first),
        Some(TerminalEffectStateV1::AllSettled)
    );

    let next = rollout.next_sequence();
    owner.begin_terminal_scope(&rollout, next);
    assert_eq!(owner.terminal_state(&rollout, first), None);
    assert_eq!(
        owner.terminal_state(&rollout, next),
        Some(TerminalEffectStateV1::NotDispatched)
    );
    let ticket = owner
        .open_tool(
            &mut rollout,
            &workspace,
            TurnId(2),
            0,
            &call,
            Capability::ReversibleLocal,
        )
        .unwrap();
    owner
        .settle(
            &mut rollout,
            ticket,
            effects::Settlement::Unknown("operator cancelled".into()),
            UnknownCause::OperatorCancelled,
        )
        .unwrap();
    assert_eq!(
        owner.terminal_state(&rollout, next),
        Some(TerminalEffectStateV1::Unknown)
    );
    let last = rollout.next_sequence();
    owner.begin_terminal_scope(&rollout, last);
    assert_eq!(
        owner.terminal_state(&rollout, last),
        Some(TerminalEffectStateV1::NotDispatched)
    );
    owner.adopt_journal();
    assert_eq!(owner.terminal_state(&rollout, last), None);
    drop(rollout);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn live_terminal_scope_refuses_recovery_without_in_scope_intent() {
    let workspace = workspace("terminal-recovery");
    let mut rollout =
        Rollout::open(&workspace, &RunId("actual".into()), TenantId::default()).unwrap();
    let mut owner = EffectJournalOwner::default();
    owner
        .guard_recovery(&mut rollout, &mut Ledger::default())
        .unwrap();
    let _ticket = owner
        .open_tool(
            &mut rollout,
            &workspace,
            TurnId(1),
            0,
            &call(),
            Capability::ReversibleLocal,
        )
        .unwrap();
    let first = rollout.next_sequence();
    let mut recovered = EffectJournalOwner::default();
    recovered.begin_terminal_scope(&rollout, first);
    assert!(matches!(
        recovered.guard_recovery(&mut rollout, &mut Ledger::default()),
        Err(super::KernelError::UnknownEffects { count: 1 })
    ));
    assert_eq!(
        recovered.terminal_state(&rollout, first),
        Some(TerminalEffectStateV1::Unavailable)
    );
    drop(rollout);
    std::fs::remove_dir_all(workspace).unwrap();
}
